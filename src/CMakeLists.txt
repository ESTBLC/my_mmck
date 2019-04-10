link_directories(
    strace/
    memtrack/
    intrlist/
)

add_subdirectory(strace/)
add_subdirectory(memtrack/)
add_subdirectory(intrlist/)

add_subdirectory(tests/)
