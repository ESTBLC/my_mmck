#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <err.h>

#include "tracee.h"
#include "strace/strace.h"

static void skip_execve(pid_t pid);

pid_t start_tracee(const char *path, char *const args[])
{
    pid_t pid = fork();

    if (pid == 0)
    {
        char *env[] = {"LD_PRELOAD=src/preload/libpreload.so", NULL};
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execve(path, args, env);
        /* Tracee launched an stopped */
    }

    waitpid(pid, NULL, 0);

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    /* Skip execve */
    skip_execve(pid);

    return pid;
}

int run_tracee(pid_t pid)
{
    int status = 0;

    ptrace(PTRACE_SYSCALL, pid, NULL, 0);

    waitpid(pid, &status, 0);

    return status;
}

int single_step_tracee(pid_t pid)
{
    int status = 0;

    ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);

    waitpid(pid, &status, 0);

    return status;
}

bool has_exited(int status)
{
    return WIFEXITED(status);
}

bool is_on_syscall(int status)
{
    return WIFSTOPPED(status) && WSTOPSIG(status)  == (SIGTRAP | 0x80);
}

bool is_on_breakpoint(int status)
{
    return WSTOPSIG(status) == SIGTRAP;
}

struct user_regs_struct get_regs(pid_t pid) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    return regs;
}

void read_memory(pid_t pid, void *addr, void *buf, size_t len)
{
    struct iovec local_iovec[] = {{buf, len}};
    struct iovec remote_iovec[] = {{addr, len}};
    process_vm_readv(pid, local_iovec, 1, remote_iovec, 1, 0);
}

static void skip_execve(pid_t pid)
{
    while (1)
    {
        struct syscall *syscall = get_next_syscall(pid);
        if (syscall == NULL)
            return;

        int id = syscall->id;
        free (syscall);

        if (id == SYS_execve)
            return;
    }
}
