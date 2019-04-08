#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdbool.h>

struct syscall {
    uint64_t id;
    struct user_regs_struct regs_before;
    struct user_regs_struct regs_after;
    uint64_t return_val;
};

struct syscall catch_syscall(pid_t pid);
void match_syscall(struct syscall *syscall);

bool is_syscall(int status);

#endif
