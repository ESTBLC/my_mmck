#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <unistd.h>
#define _POSIX_C_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "elf.h"
#include "tracee/tracee.h"

static struct phdrs_info get_phdrs_info(pid_t pid);
static Elf64_Phdr *get_dynamic_phdr(pid_t pid, struct phdrs_info const *info);
static struct r_debug *_get_r_debug_addr(pid_t pid, Elf64_Phdr const *phdr, void *base_addr);

static int open_auxv_file(pid_t pid);
static Elf64_auxv_t auxv_read_one_entry(int fd);

static void match_phdr_info(Elf64_auxv_t const *auxv_entry, struct phdrs_info *info);
static bool is_phdr_info_full(struct phdrs_info const *info);
static Elf64_Phdr *get_phdr_addr(struct phdrs_info const *info, int index);
static void get_tracee_phdr(pid_t pid, void *addr, Elf64_Phdr *phdr);
static Elf64_Dyn *get_tracee_dyn(pid_t pid, void *addr, Elf64_Dyn *dyn);
static bool is_dynamic_phdr(Elf64_Phdr const *phdr);
static bool is_dt_debug(Elf64_Dyn const *dyn);

struct r_debug *get_r_debug_addr(pid_t pid)
{
    struct phdrs_info phdrs_info = get_phdrs_info(pid);
    Elf64_Phdr *phdr = get_dynamic_phdr(pid, &phdrs_info);
    struct r_debug *addr = NULL;

    while (addr == NULL)
    {
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        if (is_on_syscall())
        addr = _get_r_debug_addr(pid, phdr, phdrs_info.phdrs);
    }

    free(phdr);

    return addr;
}

struct r_debug get_r_debug(pid_t pid, struct r_debug *addr)
{
    struct r_debug r_debug;

    read_memory(pid, addr, &r_debug, sizeof(r_debug));

    return r_debug;
}

void print_link_map(pid_t pid, struct link_map *link_map)
{

    struct link_map elm;
    read_memory(pid, link_map, &elm, sizeof(elm));
    link_map = elm.l_next;

    while (link_map != NULL)
    {
        read_memory(pid, link_map, &elm, sizeof(elm));
        printf("LD: Name = %s\t Addr = %p\n", elm.l_name, (void *)elm.l_addr);

        link_map = elm.l_next;
    }
}

static struct phdrs_info get_phdrs_info(pid_t pid)
{
    int fd = open_auxv_file(pid);

    struct phdrs_info info = {-1, -1, NULL};
    while (!is_phdr_info_full(&info)) {
        Elf64_auxv_t auxv_entry = auxv_read_one_entry(fd);
        match_phdr_info(&auxv_entry, &info);
    }

    return info;
}

static Elf64_Phdr *get_dynamic_phdr(pid_t pid, struct phdrs_info const *info)
{
    Elf64_Phdr *phdr = malloc(sizeof(*phdr));
    for (int index = 0; index < info->phdr_num; ++index) {
        void *phdr_addr = get_phdr_addr(info, index);
        get_tracee_phdr(pid, phdr_addr, phdr);
        if (is_dynamic_phdr(phdr)) {
            return phdr;
        }
    }

    return NULL;
}

static struct r_debug *_get_r_debug_addr(pid_t pid, Elf64_Phdr const *phdr, void *base_addr)
{
    Elf64_Dyn *dyn = malloc(sizeof(*dyn));
    void *dyn_addr = (void *)((uint64_t)phdr->p_vaddr + (uint64_t)base_addr);

    /* Weird trick to get fisrt dyn */ //TODO: remove it
    for ( ; (dyn = get_tracee_dyn(pid, dyn_addr, dyn))->d_tag != DT_NULL; ++dyn_addr) {
        if (is_dt_debug(dyn)) {
            // Get ptr to r_debug fron Elf64_Dyn
            struct r_debug *ptr = (struct r_debug *)dyn->d_un.d_ptr;
            free(dyn);

            return ptr;
        }
    }

    free(dyn);

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

static Elf64_Phdr *get_phdr_addr(struct phdrs_info const *info, int index)
{
    return info->phdrs + info->phdr_ent * index;
}

static void get_tracee_phdr(pid_t pid, void *addr, Elf64_Phdr *phdr)
{
    read_memory(pid, addr, phdr, sizeof(*phdr));
}

static Elf64_Dyn *get_tracee_dyn(pid_t pid, void *addr, Elf64_Dyn *dyn)
{
    read_memory(pid, addr, dyn, sizeof(*dyn));

    return dyn;
}

static bool is_dynamic_phdr(Elf64_Phdr const *phdr)
{
    return phdr->p_type == PT_DYNAMIC;
}

static bool is_dt_debug(Elf64_Dyn const *dyn)
{
    return dyn->d_tag == DT_DEBUG;
}
