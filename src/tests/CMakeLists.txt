add_executable(tests
    test.c
)

target_link_libraries(tests
    memtrack
)

add_executable(sample
    sample.c
)
