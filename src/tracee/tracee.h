#ifndef TRACEE_H
#define TRACEE_H

#include <sys/types.h>

pid_t start_tracee(const char *path, char *const args[]);

#endif
