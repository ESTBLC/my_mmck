#ifndef ELF_H
#define ELF_H

#include <sys/types.h>
#include <elf.h>

struct phdrs_info {
    int phdr_num;
    int phdr_ent;
    void *phdrs;
};

struct r_debug *get_r_debug_addr(pid_t pid);
struct r_debug get_r_debug(pid_t pid, struct r_debug *addr);

#endif
