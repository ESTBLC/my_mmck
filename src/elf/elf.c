#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <unistd.h>
#define _POSIX_C_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "elf.h"

static int open_auxv_file(pid_t pid);
static Elf64_auxv_t auxv_read_one_entry(int fd);

static void match_phdr_info(Elf64_auxv_t const *auxv_entry, struct phdrs_info *info);
static bool is_phdr_info_full(struct phdrs_info const *info);
static Elf64_Phdr *get_phdr_at_index(struct phdrs_info const *info, int index);
static bool is_dynamic_phdr(Elf64_Phdr *phdr);
static bool is_dt_debug(Elf64_Dyn *dyn);

struct phdrs_info get_pid_phdr_info(pid_t pid)
{
    int fd = open_auxv_file(pid);

    struct phdrs_info info = {-1, -1, NULL};
    while (!is_phdr_info_full(&info)) {
        Elf64_auxv_t auxv_entry = auxv_read_one_entry(fd);
        match_phdr_info(&auxv_entry, &info);
    }

    return info;
}

Elf64_Phdr *get_dynamic_phdr(struct phdrs_info const *info)
{
    for (int index = 0; index < info->phdr_num; ++index) {
        Elf64_Phdr *phdr = get_phdr_at_index(info, index);
        if (is_dynamic_phdr(phdr)) {
            return phdr;
        }
    }

    return NULL;
}

struct r_debug *get_r_debug(Elf64_Phdr const *phdr, void *base_addr)
{
    Elf64_Dyn *dyn = (Elf64_Dyn *)((uint64_t)phdr->p_vaddr + (uint64_t)base_addr);
    for ( ; dyn->d_tag != DT_NULL; ++dyn) {
        if (is_dt_debug(dyn)) {
            // Get ptr to r_debug fron Elf64_Dyn
            return (struct r_debug *)dyn->d_un.d_ptr;
        }
    }

    return NULL;
}

static int open_auxv_file(pid_t pid)
{
    char file_name[100];

    sprintf(file_name, "/proc/%i/auxv", pid);

    return open(file_name, O_RDONLY);
}

static Elf64_auxv_t auxv_read_one_entry(int fd)
{
    Elf64_auxv_t auxv;

    read(fd, &auxv, 2*sizeof(uint64_t));

    return auxv;
}

static void match_phdr_info(Elf64_auxv_t const *auxv_entry, struct phdrs_info *info)
{
    switch (auxv_entry->a_type) {
        case AT_PHDR:
            info->phdrs = (void *)auxv_entry->a_un.a_val;
            break;

        case AT_PHNUM:
            info->phdr_num = auxv_entry->a_un.a_val;
            break;

        case AT_PHENT:
            info->phdr_ent = auxv_entry->a_un.a_val;
            break;

        default:
            break;
    }
}

static bool is_phdr_info_full(struct phdrs_info const *info)
{
    return info->phdr_num != -1 && info->phdr_ent != -1 && info->phdrs != NULL;
}

static Elf64_Phdr *get_phdr_at_index(struct phdrs_info const *info, int index)
{
    return info->phdrs + info->phdr_ent * index;
}

static bool is_dynamic_phdr(Elf64_Phdr *phdr)
{
    return phdr->p_type == PT_DYNAMIC;
}

static bool is_dt_debug(Elf64_Dyn *dyn)
{
    return dyn->d_tag == DT_DEBUG;
}
