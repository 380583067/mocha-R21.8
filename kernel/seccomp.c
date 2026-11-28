/*
 * linux/kernel/seccomp.c
 *
 * Copyright 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 *
 * Copyright (C) 2012 Google, Inc.
 * Will Drewry <wad@chromium.org>
 *
 * This defines a simple but solid secure-computing facility.
 *
 * Mode 1 uses a fixed list of allowed system calls.
 * Mode 2 allows user-defined system call filters in the form
 *        of Berkeley Packet Filters/Linux Socket Filters.
 */

#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

/* #define SECCOMP_DEBUG 1 */

#ifdef CONFIG_SECCOMP_FILTER
#include <asm/syscall.h>
#include <linux/filter.h>
#include <asm/unaligned.h>
/* 3.10 vlan API absent in this tree */
#define vlan_tx_tag_get(skb)	(0)
#define vlan_tx_tag_present(skb)	(0)
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/tracehook.h>
#include <linux/uaccess.h>

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object lifetime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @len: the number of instructions in the program
 * @insns: the BPF program instructions to evaluate
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @usage).
 */
struct seccomp_filter {
	atomic_t usage;
	struct seccomp_filter *prev;
	unsigned short len;  /* Instruction count */
	struct sock_filter insns[];
};

/* Limit any path through the tree to 256KB worth of instructions. */
#define MAX_INSNS_PER_PATH ((1 << 18) / sizeof(struct sock_filter))

/**
 * get_u32 - returns a u32 offset into data
 * @data: a unsigned 64 bit value
 * @index: 0 or 1 to return the first or second 32-bits
 *
 * This inline exists to hide the length of unsigned long.  If a 32-bit
 * unsigned long is passed in, it will be extended and the top 32-bits will be
 * 0. If it is a 64-bit unsigned long, then whatever data is resident will be
 * properly returned.
 *
 * Endianness is explicitly ignored and left for BPF program authors to manage
 * as per the specific architecture.
 */
static inline u32 get_u32(u64 data, int index)
{
	return ((u32 *)&data)[index];
}

/* Helper for bpf_load below. */
#define BPF_DATA(_name) offsetof(struct seccomp_data, _name)
/**
 * bpf_load: checks and returns a pointer to the requested offset
 * @off: offset into struct seccomp_data to load from
 *
 * Returns the requested 32-bits of data.
 * seccomp_check_filter() should assure that @off is 32-bit aligned
 * and not out of bounds.  Failure to do so is a BUG.
 */
u32 seccomp_bpf_load(int off)
{
	struct pt_regs *regs = task_pt_regs(current);
	if (off == BPF_DATA(nr))
		return syscall_get_nr(current, regs);
	if (off == BPF_DATA(arch))
		return syscall_get_arch(current, regs);
	if (off >= BPF_DATA(args[0]) && off < BPF_DATA(args[6])) {
		unsigned long value;
		int arg = (off - BPF_DATA(args[0])) / sizeof(u64);
		int index = !!(off % sizeof(u64));
		syscall_get_arguments(current, regs, arg, 1, &value);
		return get_u32(value, index);
	}
	if (off == BPF_DATA(instruction_pointer))
		return get_u32(KSTK_EIP(current), 0);
	if (off == BPF_DATA(instruction_pointer) + sizeof(u32))
		return get_u32(KSTK_EIP(current), 1);
	/* seccomp_check_filter should make this impossible. */
	BUG();
}

/**
 *	seccomp_check_filter - verify seccomp filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Takes a previously checked filter (by sk_chk_filter) and
 * redirects all filter code that loads struct sk_buff data
 * and related data through seccomp_bpf_load.  It also
 * enforces length and alignment checking of those loads.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
static int seccomp_check_filter(struct sock_filter *filter, unsigned int flen)
{
	int pc;
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;
		u32 k = ftest->k;

		switch (code) {
		case BPF_S_LD_W_ABS:
			ftest->code = BPF_S_ANC_SECCOMP_LD_W;
			/* 32-bit aligned and not out of bounds. */
			if (k >= sizeof(struct seccomp_data) || k & 3)
				return -EINVAL;
			continue;
		case BPF_S_LD_W_LEN:
			ftest->code = BPF_S_LD_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		case BPF_S_LDX_W_LEN:
			ftest->code = BPF_S_LDX_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		/* Explicitly include allowed calls. */
		case BPF_S_RET_K:
		case BPF_S_RET_A:
		case BPF_S_ALU_ADD_K:
		case BPF_S_ALU_ADD_X:
		case BPF_S_ALU_SUB_K:
		case BPF_S_ALU_SUB_X:
		case BPF_S_ALU_MUL_K:
		case BPF_S_ALU_MUL_X:
		case BPF_S_ALU_DIV_X:
		case BPF_S_ALU_AND_K:
		case BPF_S_ALU_AND_X:
		case BPF_S_ALU_OR_K:
		case BPF_S_ALU_OR_X:
		case BPF_S_ALU_XOR_K:
		case BPF_S_ALU_XOR_X:
		case BPF_S_ALU_LSH_K:
		case BPF_S_ALU_LSH_X:
		case BPF_S_ALU_RSH_K:
		case BPF_S_ALU_RSH_X:
		case BPF_S_ALU_NEG:
		case BPF_S_LD_IMM:
		case BPF_S_LDX_IMM:
		case BPF_S_MISC_TAX:
		case BPF_S_MISC_TXA:
		case BPF_S_ALU_DIV_K:
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
		case BPF_S_ST:
		case BPF_S_STX:
		case BPF_S_JMP_JA:
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_K:
		case BPF_S_JMP_JSET_X:
			continue;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * seccomp_run_filters - evaluates all seccomp filters against @syscall
 * @syscall: number of the current system call
 *
 * Returns valid seccomp BPF response codes.
 */
/*--- classic-BPF helpers copied from the 3.10 base net/core/filter.c ---*/
static int check_load_and_stores(struct sock_filter *filter, int flen);
static inline void *load_pointer(const struct sk_buff *skb, int k,
				 unsigned int size, void *buffer)
{
	if (k >= 0)
		return skb_header_pointer(skb, k, size, buffer);
	return bpf_internal_load_pointer_neg_helper(skb, k, size);
}

static unsigned int seccomp_run_cbpf(const struct sk_buff *skb,
			   const struct sock_filter *fentry)
{
	void *ptr;
	u32 A = 0;			/* Accumulator */
	u32 X = 0;			/* Index Register */
	u32 mem[BPF_MEMWORDS];		/* Scratch Memory Store */
	u32 tmp;
	int k;

	/*
	 * Process array of filter instructions.
	 */
	for (;; fentry++) {
#if defined(CONFIG_X86_32)
#define	K (fentry->k)
#else
		const u32 K = fentry->k;
#endif

		switch (fentry->code) {
		case BPF_S_ALU_ADD_X:
			A += X;
			continue;
		case BPF_S_ALU_ADD_K:
			A += K;
			continue;
		case BPF_S_ALU_SUB_X:
			A -= X;
			continue;
		case BPF_S_ALU_SUB_K:
			A -= K;
			continue;
		case BPF_S_ALU_MUL_X:
			A *= X;
			continue;
		case BPF_S_ALU_MUL_K:
			A *= K;
			continue;
		case BPF_S_ALU_DIV_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
		case BPF_S_ALU_DIV_K:
			A /= K;
			continue;
		case BPF_S_ALU_MOD_X:
			if (X == 0)
				return 0;
			A %= X;
			continue;
		case BPF_S_ALU_MOD_K:
			A %= K;
			continue;
		case BPF_S_ALU_AND_X:
			A &= X;
			continue;
		case BPF_S_ALU_AND_K:
			A &= K;
			continue;
		case BPF_S_ALU_OR_X:
			A |= X;
			continue;
		case BPF_S_ALU_OR_K:
			A |= K;
			continue;
		case BPF_S_ANC_ALU_XOR_X:
		case BPF_S_ALU_XOR_X:
			A ^= X;
			continue;
		case BPF_S_ALU_XOR_K:
			A ^= K;
			continue;
		case BPF_S_ALU_LSH_X:
			A <<= X;
			continue;
		case BPF_S_ALU_LSH_K:
			A <<= K;
			continue;
		case BPF_S_ALU_RSH_X:
			A >>= X;
			continue;
		case BPF_S_ALU_RSH_K:
			A >>= K;
			continue;
		case BPF_S_ALU_NEG:
			A = -A;
			continue;
		case BPF_S_JMP_JA:
			fentry += K;
			continue;
		case BPF_S_JMP_JGT_K:
			fentry += (A > K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGE_K:
			fentry += (A >= K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JEQ_K:
			fentry += (A == K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JSET_K:
			fentry += (A & K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGT_X:
			fentry += (A > X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGE_X:
			fentry += (A >= X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JEQ_X:
			fentry += (A == X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JSET_X:
			fentry += (A & X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_LD_W_ABS:
			k = K;
load_w:
			ptr = load_pointer(skb, k, 4, &tmp);
			if (ptr != NULL) {
				A = get_unaligned_be32(ptr);
				continue;
			}
			return 0;
		case BPF_S_LD_H_ABS:
			k = K;
load_h:
			ptr = load_pointer(skb, k, 2, &tmp);
			if (ptr != NULL) {
				A = get_unaligned_be16(ptr);
				continue;
			}
			return 0;
		case BPF_S_LD_B_ABS:
			k = K;
load_b:
			ptr = load_pointer(skb, k, 1, &tmp);
			if (ptr != NULL) {
				A = *(u8 *)ptr;
				continue;
			}
			return 0;
		case BPF_S_LD_W_LEN:
			A = skb->len;
			continue;
		case BPF_S_LDX_W_LEN:
			X = skb->len;
			continue;
		case BPF_S_LD_W_IND:
			k = X + K;
			goto load_w;
		case BPF_S_LD_H_IND:
			k = X + K;
			goto load_h;
		case BPF_S_LD_B_IND:
			k = X + K;
			goto load_b;
		case BPF_S_LDX_B_MSH:
			ptr = load_pointer(skb, K, 1, &tmp);
			if (ptr != NULL) {
				X = (*(u8 *)ptr & 0xf) << 2;
				continue;
			}
			return 0;
		case BPF_S_LD_IMM:
			A = K;
			continue;
		case BPF_S_LDX_IMM:
			X = K;
			continue;
		case BPF_S_LD_MEM:
			A = mem[K];
			continue;
		case BPF_S_LDX_MEM:
			X = mem[K];
			continue;
		case BPF_S_MISC_TAX:
			X = A;
			continue;
		case BPF_S_MISC_TXA:
			A = X;
			continue;
		case BPF_S_RET_K:
			return K;
		case BPF_S_RET_A:
			return A;
		case BPF_S_ST:
			mem[K] = A;
			continue;
		case BPF_S_STX:
			mem[K] = X;
			continue;
		case BPF_S_ANC_PROTOCOL:
			A = ntohs(skb->protocol);
			continue;
		case BPF_S_ANC_PKTTYPE:
			A = skb->pkt_type;
			continue;
		case BPF_S_ANC_IFINDEX:
			if (!skb->dev)
				return 0;
			A = skb->dev->ifindex;
			continue;
		case BPF_S_ANC_MARK:
			A = skb->mark;
			continue;
		case BPF_S_ANC_QUEUE:
			A = skb->queue_mapping;
			continue;
		case BPF_S_ANC_HATYPE:
			if (!skb->dev)
				return 0;
			A = skb->dev->type;
			continue;
		case BPF_S_ANC_RXHASH:
			A = skb->rxhash;
			continue;
		case BPF_S_ANC_CPU:
			A = raw_smp_processor_id();
			continue;
		case BPF_S_ANC_VLAN_TAG:
			A = vlan_tx_tag_get(skb);
			continue;
		case BPF_S_ANC_VLAN_TAG_PRESENT:
			A = !!vlan_tx_tag_present(skb);
			continue;
		case BPF_S_ANC_PAY_OFFSET:
			A = __skb_get_poff(skb);
			continue;
		case BPF_S_ANC_NLATTR: {
			struct nlattr *nla;

			if (skb_is_nonlinear(skb))
				return 0;
			if (skb->len < sizeof(struct nlattr))
				return 0;
			if (A > skb->len - sizeof(struct nlattr))
				return 0;

			nla = nla_find((struct nlattr *)&skb->data[A],
				       skb->len - A, X);
			if (nla)
				A = (void *)nla - (void *)skb->data;
			else
				A = 0;
			continue;
		}
		case BPF_S_ANC_NLATTR_NEST: {
			struct nlattr *nla;

			if (skb_is_nonlinear(skb))
				return 0;
			if (skb->len < sizeof(struct nlattr))
				return 0;
			if (A > skb->len - sizeof(struct nlattr))
				return 0;

			nla = (struct nlattr *)&skb->data[A];
			if (nla->nla_len > skb->len - A)
				return 0;

			nla = nla_find_nested(nla, X);
			if (nla)
				A = (void *)nla - (void *)skb->data;
			else
				A = 0;
			continue;
		}
#ifdef CONFIG_SECCOMP_FILTER
		case BPF_S_ANC_SECCOMP_LD_W:
			A = seccomp_bpf_load(fentry->k);
			continue;
#endif
		default:
			WARN_RATELIMIT(1, "Unknown code:%u jt:%u tf:%u k:%u\n",
				       fentry->code, fentry->jt,
				       fentry->jf, fentry->k);
			return 0;
		}
	}

	return 0;
}

static int seccomp_chk_cbpf(struct sock_filter *filter, unsigned int flen)
{
	/*
	 * Valid instructions are initialized to non-0.
	 * Invalid instructions are initialized to 0.
	 */
	static const u8 codes[] = {
		[BPF_ALU|BPF_ADD|BPF_K]  = BPF_S_ALU_ADD_K,
		[BPF_ALU|BPF_ADD|BPF_X]  = BPF_S_ALU_ADD_X,
		[BPF_ALU|BPF_SUB|BPF_K]  = BPF_S_ALU_SUB_K,
		[BPF_ALU|BPF_SUB|BPF_X]  = BPF_S_ALU_SUB_X,
		[BPF_ALU|BPF_MUL|BPF_K]  = BPF_S_ALU_MUL_K,
		[BPF_ALU|BPF_MUL|BPF_X]  = BPF_S_ALU_MUL_X,
		[BPF_ALU|BPF_DIV|BPF_X]  = BPF_S_ALU_DIV_X,
		[BPF_ALU|BPF_MOD|BPF_K]  = BPF_S_ALU_MOD_K,
		[BPF_ALU|BPF_MOD|BPF_X]  = BPF_S_ALU_MOD_X,
		[BPF_ALU|BPF_AND|BPF_K]  = BPF_S_ALU_AND_K,
		[BPF_ALU|BPF_AND|BPF_X]  = BPF_S_ALU_AND_X,
		[BPF_ALU|BPF_OR|BPF_K]   = BPF_S_ALU_OR_K,
		[BPF_ALU|BPF_OR|BPF_X]   = BPF_S_ALU_OR_X,
		[BPF_ALU|BPF_XOR|BPF_K]  = BPF_S_ALU_XOR_K,
		[BPF_ALU|BPF_XOR|BPF_X]  = BPF_S_ALU_XOR_X,
		[BPF_ALU|BPF_LSH|BPF_K]  = BPF_S_ALU_LSH_K,
		[BPF_ALU|BPF_LSH|BPF_X]  = BPF_S_ALU_LSH_X,
		[BPF_ALU|BPF_RSH|BPF_K]  = BPF_S_ALU_RSH_K,
		[BPF_ALU|BPF_RSH|BPF_X]  = BPF_S_ALU_RSH_X,
		[BPF_ALU|BPF_NEG]        = BPF_S_ALU_NEG,
		[BPF_LD|BPF_W|BPF_ABS]   = BPF_S_LD_W_ABS,
		[BPF_LD|BPF_H|BPF_ABS]   = BPF_S_LD_H_ABS,
		[BPF_LD|BPF_B|BPF_ABS]   = BPF_S_LD_B_ABS,
		[BPF_LD|BPF_W|BPF_LEN]   = BPF_S_LD_W_LEN,
		[BPF_LD|BPF_W|BPF_IND]   = BPF_S_LD_W_IND,
		[BPF_LD|BPF_H|BPF_IND]   = BPF_S_LD_H_IND,
		[BPF_LD|BPF_B|BPF_IND]   = BPF_S_LD_B_IND,
		[BPF_LD|BPF_IMM]         = BPF_S_LD_IMM,
		[BPF_LDX|BPF_W|BPF_LEN]  = BPF_S_LDX_W_LEN,
		[BPF_LDX|BPF_B|BPF_MSH]  = BPF_S_LDX_B_MSH,
		[BPF_LDX|BPF_IMM]        = BPF_S_LDX_IMM,
		[BPF_MISC|BPF_TAX]       = BPF_S_MISC_TAX,
		[BPF_MISC|BPF_TXA]       = BPF_S_MISC_TXA,
		[BPF_RET|BPF_K]          = BPF_S_RET_K,
		[BPF_RET|BPF_A]          = BPF_S_RET_A,
		[BPF_ALU|BPF_DIV|BPF_K]  = BPF_S_ALU_DIV_K,
		[BPF_LD|BPF_MEM]         = BPF_S_LD_MEM,
		[BPF_LDX|BPF_MEM]        = BPF_S_LDX_MEM,
		[BPF_ST]                 = BPF_S_ST,
		[BPF_STX]                = BPF_S_STX,
		[BPF_JMP|BPF_JA]         = BPF_S_JMP_JA,
		[BPF_JMP|BPF_JEQ|BPF_K]  = BPF_S_JMP_JEQ_K,
		[BPF_JMP|BPF_JEQ|BPF_X]  = BPF_S_JMP_JEQ_X,
		[BPF_JMP|BPF_JGE|BPF_K]  = BPF_S_JMP_JGE_K,
		[BPF_JMP|BPF_JGE|BPF_X]  = BPF_S_JMP_JGE_X,
		[BPF_JMP|BPF_JGT|BPF_K]  = BPF_S_JMP_JGT_K,
		[BPF_JMP|BPF_JGT|BPF_X]  = BPF_S_JMP_JGT_X,
		[BPF_JMP|BPF_JSET|BPF_K] = BPF_S_JMP_JSET_K,
		[BPF_JMP|BPF_JSET|BPF_X] = BPF_S_JMP_JSET_X,
	};
	int pc;
	bool anc_found;

	if (flen == 0 || flen > BPF_MAXINSNS)
		return -EINVAL;

	/* check the filter code now */
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;

		if (code >= ARRAY_SIZE(codes))
			return -EINVAL;
		code = codes[code];
		if (!code)
			return -EINVAL;
		/* Some instructions need special checks */
		switch (code) {
		case BPF_S_ALU_DIV_K:
		case BPF_S_ALU_MOD_K:
			/* check for division by zero */
			if (ftest->k == 0)
				return -EINVAL;
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
		case BPF_S_ST:
		case BPF_S_STX:
			/* check for invalid memory addresses */
			if (ftest->k >= BPF_MEMWORDS)
				return -EINVAL;
			break;
		case BPF_S_JMP_JA:
			/*
			 * Note, the large ftest->k might cause loops.
			 * Compare this with conditional jumps below,
			 * where offsets are limited. --ANK (981016)
			 */
			if (ftest->k >= (unsigned int)(flen-pc-1))
				return -EINVAL;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* for conditionals both must be safe */
			if (pc + ftest->jt + 1 >= flen ||
			    pc + ftest->jf + 1 >= flen)
				return -EINVAL;
			break;
		case BPF_S_LD_W_ABS:
		case BPF_S_LD_H_ABS:
		case BPF_S_LD_B_ABS:
			anc_found = false;
#define ANCILLARY(CODE) case SKF_AD_OFF + SKF_AD_##CODE:	\
				code = BPF_S_ANC_##CODE;	\
				anc_found = true;		\
				break
			switch (ftest->k) {
			ANCILLARY(PROTOCOL);
			ANCILLARY(PKTTYPE);
			ANCILLARY(IFINDEX);
			ANCILLARY(NLATTR);
			ANCILLARY(NLATTR_NEST);
			ANCILLARY(MARK);
			ANCILLARY(QUEUE);
			ANCILLARY(HATYPE);
			ANCILLARY(RXHASH);
			ANCILLARY(CPU);
			ANCILLARY(ALU_XOR_X);
			ANCILLARY(VLAN_TAG);
			ANCILLARY(VLAN_TAG_PRESENT);
			ANCILLARY(PAY_OFFSET);
			}

			/* ancillary operation unknown or unsupported */
			if (anc_found == false && ftest->k >= SKF_AD_OFF)
				return -EINVAL;
		}
		ftest->code = code;
	}

	/* last instruction must be a RET code */
	switch (filter[flen - 1].code) {
	case BPF_S_RET_K:
	case BPF_S_RET_A:
		return check_load_and_stores(filter, flen);
	}
	return -EINVAL;
}

static u32 seccomp_run_filters(int syscall)
{
	struct seccomp_filter *f = ACCESS_ONCE(current->seccomp.filter);
	u32 ret = SECCOMP_RET_ALLOW;

	/* Ensure unexpected behavior doesn't result in failing open. */
	if (unlikely(WARN_ON(f == NULL)))
		return SECCOMP_RET_KILL;

	/* Make sure cross-thread synced filter points somewhere sane. */
	smp_read_barrier_depends();

	/*
	 * All filters in the list are evaluated and the lowest BPF return
	 * value always takes priority (ignoring the DATA).
	 */
	for (; f; f = f->prev) {
		u32 cur_ret = seccomp_run_cbpf(NULL, f->insns);
		
		if ((cur_ret & SECCOMP_RET_ACTION) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}
	return ret;
}
#endif /* CONFIG_SECCOMP_FILTER */

static inline bool seccomp_may_assign_mode(unsigned long seccomp_mode)
{
	assert_spin_locked(&current->sighand->siglock);

	if (current->seccomp.mode && current->seccomp.mode != seccomp_mode)
		return false;

	return true;
}

static inline void seccomp_assign_mode(struct task_struct *task,
				       unsigned long seccomp_mode)
{
	assert_spin_locked(&task->sighand->siglock);

	task->seccomp.mode = seccomp_mode;
	/*
	 * Make sure TIF_SECCOMP cannot be set before the mode (and
	 * filter) is set.
	 */
	smp_mb();
	set_tsk_thread_flag(task, TIF_SECCOMP);
}

#ifdef CONFIG_SECCOMP_FILTER
/* Returns 1 if the parent is an ancestor of the child. */
static int is_ancestor(struct seccomp_filter *parent,
		       struct seccomp_filter *child)
{
	/* NULL is the root ancestor. */
	if (parent == NULL)
		return 1;
	for (; child; child = child->prev)
		if (child == parent)
			return 1;
	return 0;
}

/**
 * seccomp_can_sync_threads: checks if all threads can be synchronized
 *
 * Expects sighand and cred_guard_mutex locks to be held.
 *
 * Returns 0 on success, -ve on error, or the pid of a thread which was
 * either not in the correct seccomp mode or it did not have an ancestral
 * seccomp filter.
 */
static inline pid_t seccomp_can_sync_threads(void)
{
	struct task_struct *thread, *caller;

	BUG_ON(!mutex_is_locked(&current->signal->cred_guard_mutex));
	assert_spin_locked(&current->sighand->siglock);

	/* Validate all threads being eligible for synchronization. */
	caller = current;
	for_each_thread(caller, thread) {
		pid_t failed;

		/* Skip current, since it is initiating the sync. */
		if (thread == caller)
			continue;

		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED ||
		    (thread->seccomp.mode == SECCOMP_MODE_FILTER &&
		     is_ancestor(thread->seccomp.filter,
				 caller->seccomp.filter)))
			continue;

		/* Return the first thread that cannot be synchronized. */
		failed = task_pid_vnr(thread);
		/* If the pid cannot be resolved, then return -ESRCH */
		if (unlikely(WARN_ON(failed == 0)))
			failed = -ESRCH;
		return failed;
	}

	return 0;
}

/**
 * seccomp_sync_threads: sets all threads to use current's filter
 *
 * Expects sighand and cred_guard_mutex locks to be held, and for
 * seccomp_can_sync_threads() to have returned success already
 * without dropping the locks.
 *
 */
static inline void seccomp_sync_threads(void)
{
	struct task_struct *thread, *caller;

	BUG_ON(!mutex_is_locked(&current->signal->cred_guard_mutex));
	assert_spin_locked(&current->sighand->siglock);

	/* Synchronize all threads. */
	caller = current;
	for_each_thread(caller, thread) {
		/* Skip current, since it needs no changes. */
		if (thread == caller)
			continue;

		/* Get a task reference for the new leaf node. */
		get_seccomp_filter(caller);
		/*
		 * Drop the task reference to the shared ancestor since
		 * current's path will hold a reference.  (This also
		 * allows a put before the assignment.)
		 */
		put_seccomp_filter(thread);
		smp_store_release(&thread->seccomp.filter,
				  caller->seccomp.filter);

		/*
		 * Don't let an unprivileged task work around
		 * the no_new_privs restriction by creating
		 * a thread that sets it up, enters seccomp,
		 * then dies.
		 */
		if (task_no_new_privs(caller))
			task_set_no_new_privs(thread);

		/*
		 * Opt the other thread into seccomp if needed.
		 * As threads are considered to be trust-realm
		 * equivalent (see ptrace_may_access), it is safe to
		 * allow one thread to transition the other.
		 */
		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED)
			seccomp_assign_mode(thread, SECCOMP_MODE_FILTER);
	}
}

/**
 * seccomp_prepare_filter: Prepares a seccomp filter for use.
 * @fprog: BPF program to install
 *
 * Returns filter on success or an ERR_PTR on failure.
 */
static struct seccomp_filter *seccomp_prepare_filter(struct sock_fprog *fprog)
{
	struct seccomp_filter *filter;
	unsigned long fp_size = fprog->len * sizeof(struct sock_filter);
	unsigned long total_insns = fprog->len;
	long ret;

	if (fprog->len == 0 || fprog->len > BPF_MAXINSNS)
		return ERR_PTR(-EINVAL);
	BUG_ON(INT_MAX / fprog->len < sizeof(struct sock_filter));

	for (filter = current->seccomp.filter; filter; filter = filter->prev)
		total_insns += filter->len + 4;  /* include a 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return ERR_PTR(-ENOMEM);

	/*
	 * Installing a seccomp filter requires that the task have
	 * CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	 * This avoids scenarios where unprivileged tasks can affect the
	 * behavior of privileged children.
	 */
	if (!task_no_new_privs(current) &&
	    security_capable_noaudit(current_cred(), current_user_ns(),
				     CAP_SYS_ADMIN) != 0)
		return ERR_PTR(-EACCES);

	/* Allocate a new seccomp_filter */
	filter = kzalloc(sizeof(struct seccomp_filter) + fp_size,
			 GFP_KERNEL|__GFP_NOWARN);
	if (!filter)
		return ERR_PTR(-ENOMEM);;
	atomic_set(&filter->usage, 1);
	filter->len = fprog->len;

	/* Copy the instructions from fprog. */
	ret = -EFAULT;
	if (copy_from_user(filter->insns, fprog->filter, fp_size))
		goto fail;

	/* Check and rewrite the fprog via the skb checker */
	ret = seccomp_chk_cbpf(filter->insns, filter->len);
	if (ret)
		goto fail;

	/* Check and rewrite the fprog for seccomp use */
	ret = seccomp_check_filter(filter->insns, filter->len);
	if (ret)
		goto fail;

	return filter;

fail:
	kfree(filter);
	return ERR_PTR(ret);
}

/**
 * seccomp_prepare_user_filter - prepares a user-supplied sock_fprog
 * @user_filter: pointer to the user data containing a sock_fprog.
 *
 * Returns 0 on success and non-zero otherwise.
 */
static struct seccomp_filter *
seccomp_prepare_user_filter(const char __user *user_filter)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter = ERR_PTR(-EFAULT);

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	filter = seccomp_prepare_filter(&fprog);
out:
	return filter;
}

/**
 * seccomp_attach_filter: validate and attach filter
 * @flags:  flags to change filter behavior
 * @filter: seccomp filter to add to the current process
 *
 * Caller must be holding current->sighand->siglock lock.
 *
 * Returns 0 on success, -ve on error.
 */
static long seccomp_attach_filter(unsigned int flags,
				  struct seccomp_filter *filter)
{
	unsigned long total_insns;
	struct seccomp_filter *walker;

	assert_spin_locked(&current->sighand->siglock);

	/* Validate resulting filter length. */
	total_insns = filter->len;
	for (walker = current->seccomp.filter; walker; walker = walker->prev)
		total_insns += walker->len + 4;  /* 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return -ENOMEM;

	/* If thread sync has been requested, check that it is possible. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC) {
		int ret;

		ret = seccomp_can_sync_threads();
		if (ret)
			return ret;
	}

	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;

	/* Now that the new filter is in place, synchronize to all threads. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		seccomp_sync_threads();

	return 0;
}

/* get_seccomp_filter - increments the reference count of the filter on @tsk */
void get_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	if (!orig)
		return;
	/* Reference count is bounded by the number of total processes. */
	atomic_inc(&orig->usage);
}

static inline void seccomp_filter_free(struct seccomp_filter *filter)
{
	if (filter) {
		kfree(filter);
	}
}

/* put_seccomp_filter - decrements the ref count of tsk->seccomp.filter */
void put_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	/* Clean up single-reference branches iteratively. */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct seccomp_filter *freeme = orig;
		orig = orig->prev;
		seccomp_filter_free(freeme);
	}
}

/**
 * seccomp_send_sigsys - signals the task to allow in-process syscall emulation
 * @syscall: syscall number to send to userland
 * @reason: filter-supplied reason code to send to userland (via si_errno)
 *
 * Forces a SIGSYS with a code of SYS_SECCOMP and related sigsys info.
 */
static void seccomp_send_sigsys(int syscall, int reason)
{
	struct siginfo info;
	memset(&info, 0, sizeof(info));
	info.si_signo = SIGSYS;
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = (void __user *)KSTK_EIP(current);
	info.si_errno = reason;
	info.si_arch = syscall_get_arch(current, task_pt_regs(current));
	info.si_syscall = syscall;
	force_sig_info(SIGSYS, &info, current);
}
#endif	/* CONFIG_SECCOMP_FILTER */

/*
 * Secure computing mode 1 allows only read/write/exit/sigreturn.
 * To be fully secure this must be combined with rlimit
 * to limit the stack allocations too.
 */
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};

#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
	__NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
	0, /* null terminated */
};
#endif

int __secure_computing(int this_syscall)
{
	int exit_sig = 0;
	int *syscall;
	u32 ret;

	/*
	 * Make sure that any changes to mode from another thread have
	 * been seen after TIF_SECCOMP was seen.
	 */
	rmb();

	switch (current->seccomp.mode) {
	case SECCOMP_MODE_STRICT:
		syscall = mode1_syscalls;
#ifdef CONFIG_COMPAT
		if (is_compat_task())
			syscall = mode1_syscalls_32;
#endif
		do {
			if (*syscall == this_syscall)
				return 0;
		} while (*++syscall);
		exit_sig = SIGKILL;
		ret = SECCOMP_RET_KILL;
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER: {
		int data;
		struct pt_regs *regs = task_pt_regs(current);
		ret = seccomp_run_filters(this_syscall);
		data = ret & SECCOMP_RET_DATA;
		ret &= SECCOMP_RET_ACTION;
		switch (ret) {
		case SECCOMP_RET_ERRNO:
			/* Set low-order bits as an errno, capped at MAX_ERRNO. */
			if (data > MAX_ERRNO)
				data = MAX_ERRNO;
			syscall_set_return_value(current, regs,
						 -data, 0);
			goto skip;
		case SECCOMP_RET_TRAP:
			/* Show the handler the original registers. */
			syscall_rollback(current, regs);
			/* Let the filter pass back 16 bits of data. */
			seccomp_send_sigsys(this_syscall, data);
			goto skip;
		case SECCOMP_RET_TRACE:
			/* Skip these calls if there is no tracer. */
			if (!ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)) {
				syscall_set_return_value(current, regs,
							 -ENOSYS, 0);
				goto skip;
			}
			/* Allow the BPF to provide the event message */
			ptrace_event(PTRACE_EVENT_SECCOMP, data);
			/*
			 * The delivery of a fatal signal during event
			 * notification may silently skip tracer notification.
			 * Terminating the task now avoids executing a system
			 * call that may not be intended.
			 */
			if (fatal_signal_pending(current))
				break;
			if (syscall_get_nr(current, regs) < 0)
				goto skip;  /* Explicit request to skip. */

			return 0;
		case SECCOMP_RET_ALLOW:
			return 0;
		case SECCOMP_RET_KILL:
		default:
			break;
		}
		exit_sig = SIGSYS;
		break;
	}
#endif
	default:
		BUG();
	}

#ifdef SECCOMP_DEBUG
	dump_stack();
#endif
	audit_seccomp(this_syscall, exit_sig, ret);
	do_exit(exit_sig);
#ifdef CONFIG_SECCOMP_FILTER
skip:
	audit_seccomp(this_syscall, exit_sig, ret);
#endif
	return -1;
}

long prctl_get_seccomp(void)
{
	return current->seccomp.mode;
}

/**
 * seccomp_set_mode_strict: internal function for setting strict seccomp
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode_strict(void)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_STRICT;
	long ret = -EINVAL;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

#ifdef TIF_NOTSC
	disable_TSC();
#endif
	seccomp_assign_mode(current, seccomp_mode);
	ret = 0;

out:
	spin_unlock_irq(&current->sighand->siglock);

	return ret;
}

#ifdef CONFIG_SECCOMP_FILTER
/**
 * seccomp_set_mode_filter: internal function for setting seccomp filter
 * @flags:  flags to change filter behavior
 * @filter: struct sock_fprog containing filter
 *
 * This function may be called repeatedly to install additional filters.
 * Every filter successfully installed will be evaluated (in reverse order)
 * for each system call the task makes.
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode_filter(unsigned int flags,
				    const char __user *filter)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_FILTER;
	struct seccomp_filter *prepared = NULL;
	long ret = -EINVAL;

	/* Validate flags. */
	if (flags & ~SECCOMP_FILTER_FLAG_MASK)
		return -EINVAL;

	/* Prepare the new filter before holding any locks. */
	prepared = seccomp_prepare_user_filter(filter);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);

	/*
	 * Make sure we cannot change seccomp or nnp state via TSYNC
	 * while another thread is in the middle of calling exec.
	 */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC &&
	    mutex_lock_killable(&current->signal->cred_guard_mutex))
		goto out_free;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

	ret = seccomp_attach_filter(flags, prepared);
	if (ret)
		goto out;
	/* Do not free the successfully attached filter. */
	prepared = NULL;

	seccomp_assign_mode(current, seccomp_mode);
out:
	spin_unlock_irq(&current->sighand->siglock);
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		mutex_unlock(&current->signal->cred_guard_mutex);
out_free:
	seccomp_filter_free(prepared);
	return ret;
}
#else
static inline long seccomp_set_mode_filter(unsigned int flags,
					   const char __user *filter)
{
	return -EINVAL;
}
#endif

/* Common entry point for both prctl and syscall. */
static long do_seccomp(unsigned int op, unsigned int flags,
		       const char __user *uargs)
{
	switch (op) {
	case SECCOMP_SET_MODE_STRICT:
		if (flags != 0 || uargs != NULL)
			return -EINVAL;
		return seccomp_set_mode_strict();
	case SECCOMP_SET_MODE_FILTER:
		return seccomp_set_mode_filter(flags, uargs);
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
			 const char __user *, uargs)
{
	return do_seccomp(op, flags, uargs);
}

/**
 * prctl_set_seccomp: configures current->seccomp.mode
 * @seccomp_mode: requested mode to use
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * Returns 0 on success or -EINVAL on failure.
 */
long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
	unsigned int op;
	char __user *uargs;

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		op = SECCOMP_SET_MODE_STRICT;
		/*
		 * Setting strict mode through prctl always ignored filter,
		 * so make sure it is always NULL here to pass the internal
		 * check in do_seccomp().
		 */
		uargs = NULL;
		break;
	case SECCOMP_MODE_FILTER:
		op = SECCOMP_SET_MODE_FILTER;
		uargs = filter;
		break;
	default:
		return -EINVAL;
	}

	/* prctl interface doesn't have flags, so they are always zero. */
	return do_seccomp(op, 0, uargs);
}

static int check_load_and_stores(struct sock_filter *filter, int flen)
{
	u16 *masks, memvalid = 0; /* one bit per cell, 16 cells */
	int pc, ret = 0;

	BUILD_BUG_ON(BPF_MEMWORDS > 16);
	masks = kmalloc(flen * sizeof(*masks), GFP_KERNEL);
	if (!masks)
		return -ENOMEM;
	memset(masks, 0xff, flen * sizeof(*masks));

	for (pc = 0; pc < flen; pc++) {
		memvalid &= masks[pc];

		switch (filter[pc].code) {
		case BPF_S_ST:
		case BPF_S_STX:
			memvalid |= (1 << filter[pc].k);
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
			if (!(memvalid & (1 << filter[pc].k))) {
				ret = -EINVAL;
				goto error;
			}
			break;
		case BPF_S_JMP_JA:
			/* a jump must set masks on target */
			masks[pc + 1 + filter[pc].k] &= memvalid;
			memvalid = ~0;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* a jump must set masks on targets */
			masks[pc + 1 + filter[pc].jt] &= memvalid;
			masks[pc + 1 + filter[pc].jf] &= memvalid;
			memvalid = ~0;
			break;
		}
	}
error:
	kfree(masks);
	return ret;
}
