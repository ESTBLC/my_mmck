#ifndef TRACEE_H
#define TRACEE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>

/* Exec */
int run_to_syscall(pid_t pid);
bool has_exited(int status);

struct user_regs_struct get_regs(pid_t pid);

#endif
