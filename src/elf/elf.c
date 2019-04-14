#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <unistd.h>
#define _POSIX_C_SOURCE
#include <stdbool.h>
#include <stdio.h>

#include "elf.h"

static int open_auxv_file(pid_t pid);
static Elf64_auxv_t auxv_read_one_entry(int fd);

static void match_phdr_info(Elf64_auxv_t *auxv_entry, struct phdrs_info *info);
static bool is_phdr_info_full(struct phdrs_info *info);

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

static void match_phdr_info(Elf64_auxv_t *auxv_entry, struct phdrs_info *info)
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

static bool is_phdr_info_full(struct phdrs_info *info)
{
    return info->phdr_num != -1 && info->phdr_ent != -1 && info->phdrs != NULL;
}
