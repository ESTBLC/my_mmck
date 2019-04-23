#ifndef DYN_T
#define DYN_T

#include <sys/types.h>
#include <elf.h>

#include "elf.h"

void find_dyn(pid_t pid, void *dyn_addr, Elf64_Dyn *dyn, Elf64_Sxword tag);

#endif
