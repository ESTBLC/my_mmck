add_library(preload SHARED
    preload.c
)

target_link_libraries(preload
    dl
)
