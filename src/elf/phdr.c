#include <sys/types.h>
#include <elf.h>

#include "phdr.h"
#include "tracee/tracee.h"

static void get_tracee_phdr(pid_t pid, void *addr, Elf64_Phdr *phdr);

void find_phdr(pid_t pid, struct phdrs_info const *phdrs_info, Elf64_Phdr *phdr, uint32_t type)
{
    void *phdr_addr = phdrs_info->addr;

    for (int i = 0; i < phdrs_info->num; ++i, phdr_addr += phdrs_info->ent) {
        get_tracee_phdr(pid, phdr_addr, phdr);
        if (phdr->p_type == type) {
            break;
        }
    }
}

static void get_tracee_phdr(pid_t pid, void *addr, Elf64_Phdr *phdr)
{
    read_memory(pid, addr, phdr, sizeof(*phdr));
}
