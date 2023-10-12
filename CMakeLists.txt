project(firewall)
cmake_minimum_required(VERSION 3.25)

set(LIB_SOURCES
	./lib/packet/packet.cc
	./lib/protocols/l2/eth.cc
	./lib/protocols/l2/arp.cc
	./lib/protocols/l3/ipv4.cc
	./lib/raw/raw_socket.cc
	./lib/parser/parser.cc
	./lib/logging/logger.cc
	./lib/pcap/pcap_intf.cc
	./lib/pcap/pcap_replay.cc
	./lib/common/common.cc)

set(SERVICE_SOURCES
	./src/config/config.cc
	./src/core/core.cc
	./src/core/rule_parser.cc
	./src/events/event_mgr.cc
	./src/filters/filter.cc)

set(TOOL_PACKET_GEN_SOURCES
	./tools/packet_gen/packet_gen_config.cc
	./tools/packet_gen/packet_gen.cc)

include_directories(
	./lib
	./lib/common/
	./lib/packet/
	./lib/parser/
	./lib/protocols/l2/
	./lib/protocols/l3/
	./lib/logging/
	./lib/raw/
	./lib/pcap/
	./src/
	./src/core/
	./src/config/
	./src/events/
	./src/filters/
	./tools/packet_gen/)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function -g -ggdb")

add_library(packet_core ${LIB_SOURCES})

add_executable(fwd ${SERVICE_SOURCES})
target_link_libraries(fwd packet_core jsoncpp pthread)

add_executable(packet_gen ${TOOL_PACKET_GEN_SOURCES})
target_link_libraries(packet_gen packet_core jsoncpp pthread)



