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
#include "error.h"

#define PRELOAD "LD_PRELOAD=src/preload/libpreload.so"

static bool is_file_exist(char const *path);
static void skip_execve(pid_t pid);

pid_t start_tracee(const char *path, char *const args[])
{
    if (!is_file_exist(path)) {
        err(-1, "Fail to open executable : %s\n", get_error_str());
    }

    pid_t pid = fork();

    if (pid == -1) {
        err(-1, "Failed to fork tracee: %s\n", get_error_str());
    }


    if (pid == 0) {
        char *env[] = {PRELOAD, NULL};

        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            err(-1, "Ptraceme failed: %s\n", get_error_str());
        }

        raise(SIGSTOP);

        if (execve(path, args, env) == -1) {
            err(-1, "Execve failed: %s\n", get_error_str());
        }
        /* Tracee launched an stopped */
    }

    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {
            err(-1, "Ptrace failed to set options: %s\n", get_error_str());
    }

    /* Skip execve */
    skip_execve(pid);

    return pid;
}

int run_tracee(pid_t pid)
{
    int status = 0;

    if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) {
            err(-1, "Ptrace failed to run : %s\n", get_error_str());
    }

    waitpid(pid, &status, 0);

    return status;
}

int single_step_tracee(pid_t pid)
{
    int status = 0;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, 0) == -1) {
            err(-1, "Ptrace failed to single step : %s\n", get_error_str());

    }

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

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            err(-1, "Ptrace failed get register: %s\n", get_error_str());
    }

    return regs;
}

void read_memory(pid_t pid, void *addr, void *buf, size_t len)
{
    struct iovec local_iovec[] = {{buf, len}};
    struct iovec remote_iovec[] = {{addr, len}};
    if (process_vm_readv(pid, local_iovec, 1, remote_iovec, 1, 0) == -1) {
            err(-1, "Failed to read tracee memory: %s\n", get_error_str());
    }
}

static bool is_file_exist(char const *path)
{
    return access(path, F_OK) != -1;
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

