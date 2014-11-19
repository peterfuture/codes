cmake_minimum_required(VERSION 2.8.9)

project(codes)

#OPTION LIST
option(PROTO_ENABLE "enable proto test" OFF)


IF(DEBUG)
	message(STATUS "To build debug version")
    add_definitions(-DDEBUG)
ENDIF()

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

if(PROTO_ENABLE)
add_definitions(-DENABLE_PROTO_TEST)
add_subdirectory(proto_lib)
endif()

add_subdirectory(src bin)

