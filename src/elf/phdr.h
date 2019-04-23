#ifndef PHDR_T
#define PHDR_T

#include <sys/types.h>
#include <elf.h>

#include "elf.h"

void find_phdr(pid_t pid, struct phdrs_info const *phdrs_info, Elf64_Phdr *phdr, uint32_t type);

#endif
