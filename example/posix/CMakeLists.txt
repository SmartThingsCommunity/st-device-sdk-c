cmake_minimum_required(VERSION 3.5)
project(example)

add_executable(example example.c)

set(stdk_config ${CMAKE_CURRENT_LIST_DIR}/stdkconfig.cmake)
add_subdirectory(../.. iotcore)
target_link_libraries(example PUBLIC iotcore)
