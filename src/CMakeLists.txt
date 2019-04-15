link_directories(
    preload/
    strace/
    tracee/
    memtrack/
    intrlist/
)

add_subdirectory(preload/)
add_subdirectory(strace/)
add_subdirectory(tracee/)
add_subdirectory(memtrack/)
add_subdirectory(intrlist/)
