#ifndef AUXV_H
#define AUXV_H

#include <sys/types.h>

struct phdrs_info auxv_get_phdrs_info(pid_t pid);

#endif
