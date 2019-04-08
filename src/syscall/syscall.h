#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdbool.h>

struct syscall {
    uint64_t id;
    struct user_regs_struct regs;
};

struct syscall *catch_syscall(pid_t pid);
void match_syscall(struct syscall *syscall);

bool is_syscall(int status);

#endif
