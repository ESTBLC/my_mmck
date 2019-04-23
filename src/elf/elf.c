#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <link.h>
#include <elf.h>

#include "elf.h"
#include "dyn.h"
#include "phdr.h"
#include "auxv.h"
#include "tracee/tracee.h"

static void *find_r_debug_addr(pid_t pid);
static void get_tracee_link_map(pid_t pid, void *addr, struct link_map *link_map);
static Elf64_Dyn *find_libc_in_r_debug(pid_t pid, struct r_debug const *r_debug);

static uint32_t elf_hash(const uint8_t* name);

void get_tracee_r_debug(pid_t pid, struct r_debug *r_debug)
{
    static void *addr = NULL;
    if (addr == NULL) {
        addr = find_r_debug_addr(pid);
    }

    read_memory(pid, addr, r_debug, sizeof(*r_debug));

    while (r_debug->r_state != RT_CONSISTENT) {
        single_step_tracee(pid);
        read_memory(pid, addr, r_debug, sizeof(*r_debug));
    }
}

void print_link_map(pid_t pid, struct link_map *link_map)
{
    struct link_map elm;
    get_tracee_link_map(pid, link_map, &elm);
    link_map = elm.l_next;

    while (link_map != NULL)
    {
        get_tracee_link_map(pid, link_map, &elm);

        char name[50];
        read_memory(pid, elm.l_name, &name, 50);

        printf("LD: Name = %s\t Addr = %p\n", name, (void *)elm.l_addr);

        link_map = elm.l_next;
    }

}

void *find_libc (pid_t pid, struct link_map *link_map)
{
    while(1) {
        void *addr = link_map;
        struct link_map elm;
        get_tracee_link_map(pid, link_map, &elm);
        addr = elm.l_next;

        while (addr != NULL)
        {
            get_tracee_link_map(pid, addr, &elm);

            char name[50];
            read_memory(pid, elm.l_name, &name, 50);

            if (strstr(name, "libc") != NULL) {
                printf("LD: Name = %s\t Addr = %p\n", name, (void *)elm.l_addr);
                return elm.l_ld;
            }

            addr = elm.l_next;
        }

        single_step_tracee(pid);
    }
}

static void *find_r_debug_addr(pid_t pid)
{
    struct phdrs_info phdrs_info = auxv_get_phdrs_info(pid);
    Elf64_Phdr dyn_phdr;
    find_phdr(pid, &phdrs_info, &dyn_phdr, PT_DYNAMIC);

    Elf64_Dyn debug_dyn;
    void *dyn_addr = (void *)((uint64_t)dyn_phdr.p_vaddr + (uint64_t)phdrs_info.addr);
    find_dyn(pid, dyn_addr, &debug_dyn, DT_DEBUG);

    /* Single step util r_debug not null */
    while (debug_dyn.d_un.d_ptr == 0) {
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        find_dyn(pid, dyn_addr, &debug_dyn, DT_DEBUG);
    }

    return (void *)debug_dyn.d_un.d_ptr;
}

static void get_tracee_link_map(pid_t pid, void *addr, struct link_map *link_map)
{
    read_memory(pid, addr, link_map, sizeof(*link_map));
}

static uint32_t elf_hash(const uint8_t* name) {
    uint32_t h = 0, g;
    for (; *name; name++) {
        h = (h << 4) + *name;
        if (g = h & 0xf0000000) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

/*  */

/*  */
/* static void *find_symbol_libc(pid_t pid, char const *name) */
/* { */
/*     void *r_debug_addr = find_r_debug_addr(pid); */
/*     struct r_debug r_debug; */
/*     get_tracee_r_debug(pid, r_debug_addr, &r_debug); */
/*  */
/*     void *libc_addr = find_libc_in_r_debug(&r_debug); */
/*     Elf64_Dyn symtab; */
/*     Elf64_Dyn strtab; */
/*     find_dyn(pid, libc_addr, &symtab, DT_SYMTAB); */
/*     find_dyn(pid, libc_addr, &strtab, DT_STRTAB); */
/*  */
/*     Elf64_Sym sym; */
/*     Elf64_Sym const *sym_addr = symtab */
/* } */
