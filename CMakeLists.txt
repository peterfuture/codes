cmake_minimum_required(VERSION 2.8.9)

project(codes)

find_package(Boost 1.54 COMPONENTS program_options REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})

link_libraries(${Boost_LIBRARIES})

add_executable(code_test main.cpp)
