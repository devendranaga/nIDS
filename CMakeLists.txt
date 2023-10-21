##
# Build system for firewall and its related tooling
#
project(firewall)
cmake_minimum_required(VERSION 3.25)

include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/l2/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/l3/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/l4/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/app/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/pcap/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/tools/packet_gen/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/src/core/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/src/events/build.cmake)

set(LIB_SOURCES
	./lib/packet/packet.cc
	${LIB_SOURCES_L2}
	${LIB_SOURCES_L3}
	${LIB_SOURCES_L4}
	${LIB_SOURCES_APP}
	${LIB_SOURCES_PCAP}
	./lib/raw/raw_socket.cc
	./lib/logging/logger.cc
	./lib/crypto/crypto.cc
	./lib/common/common.cc)

set(SERVICE_SOURCES
	./src/config/config.cc
	${CORE_SRC}
	./src/parser/parser.cc
	${EVENT_MGR_SRC}
	./src/filters/filter.cc)

set(TOOL_PACKET_GEN_SOURCES
	${PKT_GEN_SRC})

include_directories(
	./lib
	./lib/common/
	./lib/packet/
	./src/parser/
	./lib/protocols/common/
	./lib/logging/
	./lib/raw/
	./lib/crypto/
	./lib/signatures/
	./src/
	./src/config/
	./src/filters/
	./tools/packet_gen/)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function -g -ggdb")

add_library(packet_core ${LIB_SOURCES})

add_executable(fwd ${SERVICE_SOURCES})
target_link_libraries(fwd packet_core jsoncpp pthread)

add_executable(packet_gen ${TOOL_PACKET_GEN_SOURCES})
target_link_libraries(packet_gen packet_core jsoncpp pthread)



