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
static Elf64_auxv_t auxv_read_one_line(int fd);
static bool is_phdr_auxv(Elf64_auxv_t *auxv);

void *get_pid_phdr(pid_t pid)
{
    int fd = open_auxv_file(pid);
    Elf64_auxv_t auxv = auxv_read_one_line(fd);
    while (is_phdr_auxv(&auxv)) {
        auxv = auxv_read_one_line(fd);
    }

    return (void *)auxv.a_un.a_val;
}

static int open_auxv_file(pid_t pid)
{
    char file_name[100];

    sprintf(file_name, "/proc/%i/auxv", pid);

    return open(file_name, O_RDONLY);
}

static Elf64_auxv_t auxv_read_one_line(int fd)
{
    Elf64_auxv_t auxv;

    read(fd, &auxv, 2*sizeof(uint64_t));

    return auxv;
}

static bool is_phdr_auxv(Elf64_auxv_t *auxv)
{
    return auxv->a_type == AT_PHDR;
}
