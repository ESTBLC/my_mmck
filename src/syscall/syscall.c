#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include "syscall.h"
#include "tracee/tracee.h"

static void execve_func(struct syscall *syscall);
static void mmap_func(struct syscall *syscall);
static void mprotect_func(struct syscall *syscall);
static void brk_func(struct syscall *syscall);

struct syscall catch_syscall(pid_t pid)
{
    struct syscall syscall;

    syscall.regs_before = get_regs(pid);
    syscall.id = syscall.regs_before.orig_rax;

    run_to_syscall(pid);

    syscall.regs_after = get_regs(pid);
    syscall.return_val = syscall.regs_after.rax;

    return syscall;
}

void match_syscall(struct syscall *syscall)
{
    switch (syscall->id)
    {
       case SYS_execve:
            execve_func(syscall);
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
            mmap_func(syscall);
            break;
        case SYS_mremap:
            printf("mremap()\n");
            break;
        case SYS_mprotect:
            mprotect_func(syscall);
            break;
        case SYS_munmap:
            printf("munmap()\n");
            break;
        case SYS_brk:
            brk_func(syscall);
            break;
        default:
            printf("SYSCALL\n");
            return;
    }
}

static void execve_func(struct syscall *syscall)
{
    printf("execve() = 0x%lx\n", (int64_t)syscall->return_val);
}

static void mmap_func(struct syscall *syscall)
{
    printf("mmap() = 0x%lx\n", (uint64_t)syscall->return_val);
}

static void mprotect_func(struct syscall *syscall)
{
    printf("mprotect() = 0x%x\n", (int)syscall->return_val);
}

static void brk_func(struct syscall *syscall)
{
    printf("brk() = 0x%lx\n", (int64_t)syscall->return_val);
}

bool is_syscall(int status)
{
    return WIFSTOPPED(status) && WSTOPSIG(status)  == (SIGTRAP | 0x80);
}
