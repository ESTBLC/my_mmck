#include <stdlib.h>

#include "strace.h"
#include "tracee/tracee.h"
#include "preload/hook_info.h"

static void *get_hook_info_addr(pid_t pid);

struct syscall *get_next_syscall(pid_t pid)
{
    int status = run_tracee(pid);
    if (has_exited(status))
        return NULL;

    return catch_syscall(pid);
}

struct syscall *catch_syscall(pid_t pid)
{
    struct syscall *syscall = malloc(sizeof(*syscall));

    syscall->regs_before = get_regs(pid);
    syscall->id = syscall->regs_before.orig_rax;

    run_tracee(pid);

    syscall->regs_after = get_regs(pid);
    syscall->return_val = syscall->regs_after.rax;

    return syscall;
}

void get_hook_info(pid_t pid, struct hook_info *info)
{
    void *addr = get_hook_info_addr(pid);
    read_memory(pid, addr, info, sizeof(*info));
}

static void *get_hook_info_addr(pid_t pid)
{
    struct user_regs_struct regs = get_regs(pid);

    return (void *)regs.rax;
}
