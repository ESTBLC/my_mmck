#include <stdlib.h>
#include <stdbool.h>

#include "strace.h"
#include "tracee.h"
#include "syscall.h"

struct syscall *get_next_syscall(pid_t pid)
{
    int status = run_to_syscall(pid);
    if (has_exited(status))
        return NULL;

    return catch_syscall(pid);
}
