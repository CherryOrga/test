cmake_minimum_required(VERSION 3.14)

project(loader)

set(CMAKE_CXX_STANDARD 17)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

add_subdirectory(shared/spdlog)
add_subdirectory(server)
add_subdirectory(tools/remote_strip)

target_include_directories(server PRIVATE ${PROJECT_SOURCE_DIR}/shared)
target_link_libraries(server PRIVATE spdlog)

target_precompile_headers(server PRIVATE ${PROJECT_SOURCE_DIR}/shared/linux-pe/linuxpe)
