cmake_minimum_required(VERSION 3.10)
project(amn01-andrea_maugeri)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)
set(EXECUTABLE_NAME ${PROJECT_NAME})

add_compile_options(-Wall)

file(GLOB MDR_LIBRARY_HEADERS lib/mdr/*.h)
file(GLOB MDR_LIBRARY_SOURCES lib/mdr/*.c)
add_library(lib-mdr ${MDR_LIBRARY_SOURCES} ${MDR_LIBRARY_HEADERS})

file(GLOB AMN01_LIBRARY_HEADERS include/*.h)
file(GLOB AMN01_LIBRARY_SOURCES src/*.c)

add_library(lib-amn01 ${AMN01_LIBRARY_SOURCES} ${AMN01_LIBRARY_HEADERS})

add_executable(${PROJECT_NAME} amn01.c )

target_link_libraries(${PROJECT_NAME} lib-amn01 lib-mdr m gmp nettle)
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
