#ifndef ELF_H
#define ELF_H

#include <sys/types.h>
#include <elf.h>
#include <link.h>

struct phdrs_info {
    int phdr_num;
    int phdr_ent;
    void *phdrs;
};

struct r_debug *get_r_debug_addr(pid_t pid);
struct r_debug get_r_debug(pid_t pid, struct r_debug *addr);

void print_link_map(pid_t pid, struct link_map *link_map);

#endif
