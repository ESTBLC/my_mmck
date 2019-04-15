#ifndef TRACEE_H
#define TRACEE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>

/* Exec */
pid_t start_tracee(const char *path, char *const args[]);
int run_tracee(pid_t pid);
int single_step_tracee(pid_t pid);

bool has_exited(int status);
bool is_on_syscall(int status);
bool is_on_breakpoint(int status);

// Memory
struct user_regs_struct get_regs(pid_t pid);
void read_memory(pid_t pid, void *addr, void *buf, size_t len);

#endif
