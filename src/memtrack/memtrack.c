#include <sys/syscall.h>
#include <stdlib.h>

#include "memtrack.h"
#include "strace/strace.h"

static void match_syscall(struct syscall const *syscall);

static void execve_func(struct syscall const *syscall);
static void mmap_func(struct syscall const *syscall);
static void mprotect_func(struct syscall const *syscall);
static void brk_func(struct syscall const *syscall);

void memtrack(pid_t pid)
{
    while(1)
    {
        struct syscall const *syscall = get_next_syscall(pid);
        if (syscall == NULL)
            return;

        match_syscall(syscall);

        free((void *)syscall);
    }
}

static void match_syscall(struct syscall const *syscall)
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

static void execve_func(struct syscall const *syscall)
{
    printf("execve() = 0x%lx\n", (int64_t)syscall->return_val);
}

static void mmap_func(struct syscall const *syscall)
{
    printf("mmap() = 0x%lx\n", (uint64_t)syscall->return_val);
}

static void mprotect_func(struct syscall const *syscall)
{
    printf("mprotect() = 0x%x\n", (int)syscall->return_val);
}

static void brk_func(struct syscall const *syscall)
{
    printf("brk() = 0x%lx\n", (int64_t)syscall->return_val);
}
