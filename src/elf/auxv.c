#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <link.h>
#include <elf.h>
#include <err.h>

#include "auxv.h"
#include "elf.h"
#include "error.h"

static int auxv_open(pid_t pid);
static Elf64_auxv_t auxv_read_entry(int fd);
static bool is_phdrs_info_full(struct phdrs_info const *info);

struct phdrs_info auxv_get_phdrs_info(pid_t pid)
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

    read(fd, &aux, 2 * sizeof(uint64_t));

    return aux;
}

static bool is_phdrs_info_full(struct phdrs_info const *info)
{
    return info->num && info->ent && info->addr;
}
