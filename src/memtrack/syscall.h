#ifndef SYSCALL_H
#define SYSCALL_H

#include "strace/strace.h"
#include "intrlist/intrlist.h"

void match_syscall(struct syscall const *syscall, intrlist_t *mem_table);

#endif
