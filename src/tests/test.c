#define _DEFAULT_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>

#include "memtrack/memtrack.c"

static void test_mmap_is_valid();

int main()
{
    test_mmap_is_valid();

    printf("TEST Passed\n");
}

static void test_mmap_is_valid()
{
    int flags = MAP_FIXED | MAP_ANONYMOUS;
    assert(mmap_is_valid(flags));
}
