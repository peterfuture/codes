cmake_minimum_required(VERSION 2.8.9)

project(codes)

find_package(Boost 1.54 COMPONENTS program_options REQUIRED)
find_package(Protobuf REQUIRED)

include_directories(include)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${PROTOBUF_INCLUDE_DIRS})

link_libraries(${Boost_LIBRARIES})

add_subdirectory(src bin)

add_subdirectory(proto_lib)