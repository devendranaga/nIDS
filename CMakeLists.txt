project(firewall)
cmake_minimum_required(VERSION 3.25)

set(LIB_SOURCES
	./lib/packet/packet.cc
	./lib/protocols/l2/eth.cc
	./lib/protocols/l2/arp.cc
	./lib/raw/raw_socket.cc
	./lib/parser/parser.cc
	./lib/logging/logger.cc
	./lib/pcap/pcap_intf.cc
	./lib/pcap/pcap_replay.cc)

set(SERVICE_SOURCES
	./src/config.cc
	./src/core.cc
	./src/rule_parser.cc
	./src/filters/filter.cc)

include_directories(
	./lib
	./lib/packet/
	./lib/parser/
	./lib/protocols/l2/
	./lib/logging/
	./lib/raw/
	./lib/pcap/
	./src/
	./src/events/
	./src/filters/)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function -g -ggdb")

add_library(packet_core ${LIB_SOURCES})

add_executable(fwd ${SERVICE_SOURCES})
target_link_libraries(fwd packet_core jsoncpp)


