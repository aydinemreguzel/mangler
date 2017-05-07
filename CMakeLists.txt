cmake_minimum_required(VERSION 2.8)

project(mangle)

set(CMAKE_SOURCE_DIR src)
set(CMAKE_BINARY_DIR bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

file(GLOB SOURCES "src/*.c")
add_executable(mangle ${SOURCES})

file(GLOB PLUGINS "plugins/*.c")
add_library(plugins SHARED ${PLUGINS})

TARGET_LINK_LIBRARIES(mangle nfnetlink netfilter_queue plugins)

# The following folder will be included
include_directories("${PROJECT_SOURCE_DIR}")
