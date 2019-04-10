#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <err.h>

#include "strace.h"
#include "tracee.h"
#include "syscall.h"

pid_t start_tracee(const char *path, char *const args[])
{
    pid_t pid = fork();

    if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execvp(path, args);
        /* Tracee launched an stopped */
    }

    waitpid(pid, NULL, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    return pid;
}

int run_to_syscall(pid_t pid) {
    while(1) {
        int status = 0;

        ptrace(PTRACE_SYSCALL, pid, NULL, 0);

        waitpid(pid, &status, 0);

        if (is_syscall(status) || has_exited(status))
            return status;
    }
}

struct user_regs_struct get_regs(pid_t pid) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    return regs;
}

bool has_exited(int status)
{
    return WIFEXITED(status);
}
