#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "preload/hook_info.h"
#include "intrlist/intrlist.h"

void match_libc(struct hook_info *info, intrlist_t *mem_table);

#endif
