cmake_minimum_required(VERSION 3.14)

if (NOT WIN32)
    message(STATUS "remote_strip tool is only built on Windows hosts")
    return()
endif()

add_executable(remote_strip
    src/main.cpp
    src/pe_image.cpp
    src/pe_image.h
    src/pdb_symbols.cpp
    src/pdb_symbols.h
)

target_include_directories(remote_strip PRIVATE
    ${PROJECT_SOURCE_DIR}/shared
)

target_compile_features(remote_strip PRIVATE cxx_std_17)

target_compile_definitions(remote_strip PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

target_link_libraries(remote_strip PRIVATE ole32 shlwapi)
