#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <link.h>
#include <elf.h>
#include <err.h>

#include "elf.h"
#include "error.h"
#include "tracee/tracee.h"

static int auxv_open(pid_t pid);
static Elf64_auxv_t auxv_read_entry(int fd);
static struct phdrs_info auxv_get_phdrs_info(int fd);
static bool is_phdrs_info_full(struct phdrs_info const *info);

static void *find_r_debug_addr(pid_t pid);
static void find_phdr(pid_t pid, struct phdrs_info const *phdrs_info, Elf64_Phdr *phdr, uint32_t type);
static void find_dyn(pid_t pid, Elf64_Phdr const *phdr, Elf64_Dyn *dyn, Elf64_Sxword tag);
static void get_tracee_phdr(pid_t pid, void *addr, Elf64_Phdr *phdr);
static void get_tracee_dyn(pid_t pid, void *addr, Elf64_Dyn *dyn);

static int auxv_open(pid_t pid)
{
    char file_name[100];

    sprintf(file_name, "/proc/%i/auxv", pid);

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        err(-1, "Failed to open auxv: %s\n", get_error_str());
    }

    return fd;
}

static Elf64_auxv_t auxv_read_entry(int fd)
{
    Elf64_auxv_t aux;

    read(fd, &aux, 2*sizeof(uint64_t));

    return aux;
}

static struct phdrs_info auxv_get_phdrs_info(pid_t pid)
{
    int fd = auxv_open(pid);

    struct phdrs_info phdrs_info = {0, 0, NULL};

    while(!is_phdrs_info_full(&phdrs_info)) {
        Elf64_auxv_t aux = auxv_read_entry(fd);
        switch (aux.a_type) {
        case AT_PHDR:
            phdrs_info.addr = (void *)aux.a_un.a_val;
            break;

        case AT_PHNUM:
            phdrs_info.num = aux.a_un.a_val;
            break;

        case AT_PHENT:
            phdrs_info.ent = aux.a_un.a_val;
            break;

        default:
            break;
        }
    }

    return phdrs_info;
}

static bool is_phdrs_info_full(struct phdrs_info const *info)
{
    return info->num && info->ent && info->addr;
}

static void *find_r_debug_addr(pid_t pid)
{
    struct phdrs_info phdrs_info = auxv_get_phdrs_info(pid);
    Elf64_Phdr dyn_phdr;
    find_phdr(pid, &phdrs_info, &dyn_phdr, PT_DYNAMIC);

    /* Hack to not pass another arg to find_dyn */
    dyn_phdr.p_paddr = (uint64_t)phdrs_info.addr;

    Elf64_Dyn debug_dyn;
    find_dyn(pid, &dyn_phdr, &debug_dyn, DT_DEBUG);

    /* Single step util r_debug not null */
    while (!debug_dyn.d_un.d_ptr) {
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        find_dyn(pid, &dyn_phdr, &debug_dyn, DT_DEBUG);
    }

    return (void *)debug_dyn.d_un.d_ptr;
}

static void find_phdr(pid_t pid, struct phdrs_info const *phdrs_info, Elf64_Phdr *phdr, uint32_t type)
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

static void find_dyn(pid_t pid, Elf64_Phdr const *phdr, Elf64_Dyn *dyn, Elf64_Sxword tag)
{
    void *dyn_addr = (void *)((uint64_t)phdr->p_vaddr + (uint64_t)phdr->p_paddr);

    while(1) {
        get_tracee_dyn(pid, dyn_addr, dyn);
        if (dyn->d_tag == tag) {
            break;
        }

    }
}

static void get_tracee_dyn(pid_t pid, void *addr, Elf64_Dyn *dyn)
{
    read_memory(pid, addr, dyn, sizeof(*dyn));
}

static Elf64_Dyn *find_libc_in_r_debug(struct r_debug const *r_debug)
{
    struct link_map *ptr = r_debug->r_map;
    while (ptr != NULL) {
        if (strstr(ptr->l_name, "libc.so")) {
                return ptr->l_ld;
        }

        ptr = ptr->l_next;
    }

    return NULL;
}
