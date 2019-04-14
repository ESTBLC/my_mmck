add_definitions(-D_GNU_SOURCE=1)

add_library(memtrack
    memtrack.c
    mem.c
)

target_link_libraries(memtrack
    strace
    intrlist
)
