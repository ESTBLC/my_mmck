#ifndef ELF_H
#define ELF_H

#include <sys/types.h>
#include <link.h>
#include <elf.h>

struct phdrs_info {
    int num;
    int ent;
    void *addr;
};

void get_tracee_r_debug(pid_t pid, struct r_debug *r_debug);
void print_link_map(pid_t pid, struct link_map *link_map);
void *find_libc(pid_t pid, struct link_map *link_map);
void *find_symbol(pid_t pid, void *libc, char const *name);

#endif
