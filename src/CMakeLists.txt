
set(SRC main.cpp)

if(PROTO_ENABLE)
list(APPEND SRC  proto_test.cpp)
endif()

if(SOCI_ENABLE)
list(APPEND SRC  soci_test.cpp)
endif()

if(OPENSSL_ENABLE)
list(APPEND SRC  openssl_test.cpp)
endif()

add_executable(code_test ${SRC})

if(PROTO_ENABLE)
target_link_libraries(code_test codec_proto)
endif()
