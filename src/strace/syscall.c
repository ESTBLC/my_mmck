#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include "syscall.h"
#include "tracee/tracee.h"

struct syscall *catch_syscall(pid_t pid)
{
    struct syscall *syscall = malloc(sizeof(*syscall));

    syscall->regs_before = get_regs(pid);
    syscall->id = syscall->regs_before.orig_rax;

    run_to_syscall(pid);

    syscall->regs_after = get_regs(pid);
    syscall->return_val = syscall->regs_after.rax;

    return syscall;
}
