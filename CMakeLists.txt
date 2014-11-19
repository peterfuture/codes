cmake_minimum_required(VERSION 2.8.9)

project(codes)

##############################################
#  OPTION
##############################################
option(PROTO_ENABLE "enable proto test" ON)
option(SOCI_ENABLE "soci-postgresql test" ON)


IF(DEBUG)
	message(STATUS "To build debug version")
    add_definitions(-DDEBUG)
ENDIF()


##############################################
#  ENV
##############################################

find_package(Boost 1.54 COMPONENTS program_options REQUIRED)

#proto
if(PROTO_ENABLE)
find_package(Protobuf REQUIRED)
add_definitions(-DENABLE_PROTO_TEST)
include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/proto_lib)
endif()

#local include
include_directories(include)
#boost include
include_directories(${Boost_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES})

##############################################
#  TARGET
##############################################
if(PROTO_ENABLE)
add_subdirectory(proto_lib)
endif()

add_subdirectory(src bin)

