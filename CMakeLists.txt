cmake_minimum_required(VERSION 2.8.9)

project(codes)

find_package(Boost 1.54 COMPONENTS program_options REQUIRED)
find_package(Protobuf REQUIRED)

#local include
include_directories(include)

#boost include
include_directories(${Boost_INCLUDE_DIRS})

#proto include
include_directories(proto_lib)
include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/proto_lib)

link_libraries(${Boost_LIBRARIES})

add_subdirectory(proto_lib)
add_subdirectory(src bin)

