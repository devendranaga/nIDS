##
# Build system for firewall and its related tooling
#
project(firewall)
cmake_minimum_required(VERSION 3.22)

include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/l2/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/l3/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/l4/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/protocols/app/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/pcap/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/raw/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/tools/packet_gen/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/src/core/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/src/events/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/src/parser/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/src/stats/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/logging/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/crypto/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/common/build.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lib/packet/build.cmake)

set(LIB_SOURCES
	${LIB_SOURCES_PACKET}
	${LIB_SOURCES_L2}
	${LIB_SOURCES_L3}
	${LIB_SOURCES_L4}
	${LIB_SOURCES_APP}
	${LIB_SOURCES_PCAP}
	${LIB_SOURCES_RAW}
	${LIB_SOURCES_LOGGING}
	${LIB_SOURCES_CRYPTO}
	${LIB_SOURCES_COMMON})

set(SERVICE_SOURCES
	./src/config/config.cc
	${CORE_SOURCES}
	${PARSER_SOURCES}
	${EVENT_MGR_SOURCES}
	${STATS_SOURCES}
	./src/filters/filter.cc)

set(TOOL_PACKET_GEN_SOURCES
	${PKT_GEN_SOURCES})

include_directories(
	./lib
	./src/parser/
	./lib/protocols/common/
	./lib/signatures/
	./src/
	./src/stats/
	./src/config/
	./src/filters/)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function -g -ggdb")

add_library(packet_core ${LIB_SOURCES})

add_executable(fwd ${SERVICE_SOURCES})
target_link_libraries(fwd packet_core jsoncpp pthread)

add_executable(packet_gen ${TOOL_PACKET_GEN_SOURCES})
target_link_libraries(packet_gen packet_core jsoncpp pthread)



