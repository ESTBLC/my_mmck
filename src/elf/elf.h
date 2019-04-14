#ifndef ELF_H
#define ELF_H

#include <sys/types.h>
#include <elf.h>

struct phdrs_info {
    int phdr_num;
    int phdr_ent;
    void *phdrs;
};

struct phdrs_info get_pid_phdr_info(pid_t pid);
Elf64_Phdr *get_dynamic_phdr(struct phdrs_info const *info);
struct r_debug *get_r_debug(Elf64_Phdr const *phdr, void *base_addr);

#endif
