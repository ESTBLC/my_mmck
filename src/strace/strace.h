#ifndef STRACE_H
#define STRACE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>

struct syscall {
    uint64_t id;
    struct user_regs_struct regs_before;
    struct user_regs_struct regs_after;
    uint64_t return_val;
};

struct syscall *get_next_syscall(pid_t pid);

#endif
