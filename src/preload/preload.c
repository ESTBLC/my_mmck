#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "preload.h"
#include "hook_info.h"

static void *(*libc_malloc)(size_t) = NULL;
static void *(*libc_calloc)(size_t, size_t) = NULL;
static void *(*libc_realloc)(void*, size_t) = NULL;
static void (*libc_free)(void*) = NULL;

static void push_info(struct hook_info const *info);

void *malloc(size_t size)
{
    if (libc_malloc == NULL)
        libc_malloc = dlsym(RTLD_NEXT, "malloc");

    void *addr = libc_malloc(size);

    struct hook_info info = {MALLOC, size, 0, 0, 0, (uint64_t)addr};

    /* Breakpoint */
    push_info(&info);

    return addr;
}

void *calloc(size_t nmemb, size_t size)
{
    if (libc_calloc == NULL)
        libc_calloc = dlsym(RTLD_NEXT, "calloc");

    void *addr = libc_calloc(nmemb, size);

    struct hook_info info = {CALLOC, nmemb, size, 0, 0, (uint64_t)addr};

    /* Breakpoint */
    push_info(&info);

    return addr;
}

void *realloc(void *ptr, size_t size)
{
    if (libc_realloc == NULL)
        libc_realloc = dlsym(RTLD_NEXT, "realloc");

    void *addr = libc_realloc(ptr, size);

    struct hook_info info = {REALLOC, (uint64_t)ptr, size, 0, 0, (uint64_t)addr};

    /* Breakpoint */
    push_info(&info);

    return addr;
}

void free(void *addr)
{
    if (libc_free == NULL)
        libc_free = dlsym(RTLD_NEXT, "free");

    struct hook_info info = {FREE, (uint64_t)addr, 0, 0, 0, 0};

    /* Breakpoint */
    push_info(&info);

    return libc_free(addr);
}

static void push_info(struct hook_info const *info)
{
    __asm__ ("mov %0, %%rax" : : "r"(info) : );

    /* Breakpoint */
    __asm__ ("int3");
}
