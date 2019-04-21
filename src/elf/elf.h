#ifndef ELF_H
#define ELF_H

#include <elf.h>

struct phdrs_info {
    int num;
    int ent;
    void *addr;
};

#endif
