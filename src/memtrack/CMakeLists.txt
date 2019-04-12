add_library(memtrack
    memtrack.c
    mem.c
)

target_link_libraries(memtrack
    strace
    intrlist
)
