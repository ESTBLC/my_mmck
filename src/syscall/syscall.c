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

    syscall->regs = get_regs(pid);
    syscall->id = syscall->regs.orig_rax;

    run_to_syscall(pid);
    // Now return of syscall

    return syscall;
}

void match_syscall(struct syscall *syscall)
{
    switch (syscall->id)
    {
        case SYS_execve:
            printf("execve()\n");
            break;
        case SYS_fork:
            printf("fork()\n");
            break;
        case SYS_vfork:
            printf("vfork()\n");
            break;
        case SYS_clone:
            printf("clone()\n");
            break;
        case SYS_exit:
            printf("exit()\n");
            break;
        case SYS_exit_group:
            printf("exit_group()\n");
            break;
        case SYS_mmap:
            printf("mmap()\n");
            break;
        case SYS_mremap:
            printf("mremap()\n");
            break;
        case SYS_mprotect:
            printf("mprotext()\n");
            break;
        case SYS_munmap:
            printf("munmap()\n");
            break;
        case SYS_brk:
            printf("brk()\n");
            break;
        default:
            printf("SYSCALL\n");
            return;
    }
}

bool is_syscall(int status)
{
    return WIFSTOPPED(status) && WSTOPSIG(status)  == (SIGTRAP | 0x80);
}
