cmake_minimum_required(VERSION 2.8.9)

PROTOBUF_GENERATE_CPP(PROTO_PERSON PROTO_PERSON_HDRS person.proto)

add_library(codec_proto STATIC ${PROTO_PERSON})
target_link_libraries(codec_proto ${PROTOBUF_LIBRARIES})

#set_target_properties(codec_proto PROPERTIES POSITION_INDEPENDENT_CODE ON)