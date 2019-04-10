#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdbool.h>

#include "strace.h"

struct syscall *catch_syscall(pid_t pid);

bool is_syscall(int status);

#endif
