#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "preload.h"
#include "hook_info.h"

static void *(*libc_malloc)(size_t) = NULL;
/* static void (*libc_free)(void*) = NULL; */

static void push_info(struct hook_info const *info);

void *malloc(size_t size)
{
    if (libc_malloc == NULL)
        libc_malloc = dlsym(RTLD_NEXT, "malloc");

    void *addr = libc_malloc(size);

    struct hook_info info = {MALLOC, addr};

    /* Breakpoint */
    push_info(&info);

    return addr;
}

static void push_info(struct hook_info const *info)
{
    __asm__ ("mov %0, %%rax" : : "r"(info) : );

    /* Breakpoint */
    __asm__ ("int3");
}

/* void free(void *addr) */
/* { */
/*     if (libc_free == NULL) */
/*         libc_free = dlsym(RTLD_NEXT, "free"); */
/*  */
/*     return libc_free(addr); */
/* } */
