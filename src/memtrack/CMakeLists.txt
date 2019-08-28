add_definitions(-D_GNU_SOURCE=1)

add_library(memtrack
    memtrack.c
    syscall.c
    allocator.c
    mapblock.c
    allocblock.c
)

target_link_libraries(memtrack
    strace
    elf
    intrlist
)
