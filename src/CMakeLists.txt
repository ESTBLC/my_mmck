link_directories(
    strace/
    memtrack/
    intrlist/
    htab/
)

add_subdirectory(strace/)
add_subdirectory(memtrack/)
add_subdirectory(intrlist/)
add_subdirectory(htab/)
