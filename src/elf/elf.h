#ifndef ELF_H
#define ELF_H

#include <sys/types.h>

struct phdrs_info {
    int phdr_num;
    int phdr_ent;
    void *phdrs;
};

struct phdrs_info get_pid_phdr_info(pid_t pid);

#endif
