obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o
# stackmap needs 4.x callchain APIs; disabled for this 3.10 port
# obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
obj-$(CONFIG_CGROUP_BPF) += cgroup.o
