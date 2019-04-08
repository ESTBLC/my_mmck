#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tracee.h"

pid_t start_tracee(const char *path, char *const args[])
{
    pid_t pid = fork();

    if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(path, args);
    }

    waitpid(pid, NULL, 0);

    return pid;
}
