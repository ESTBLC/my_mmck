#ifndef TRACEE_H
#define TRACEE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>

/* Exec */
pid_t start_tracee(const char *path, char *const args[]);
int run_to_syscall(pid_t pid);

bool is_on_syscall(int status);
bool has_exited(int status);

struct user_regs_struct get_regs(pid_t pid);

#endif
