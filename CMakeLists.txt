project(firewall)
cmake_minimum_required(VERSION 3.25)

set(LIB_SOURCES
	./lib/packet/packet.cc
	./lib/protocols/l2/eth.cc
	./lib/raw/raw_socket.cc
	./lib/logging/logger.cc)

set(SERVICE_SOURCES
	./src/config.cc
	./src/core.cc)

include_directories(
	./lib
	./lib/packet/
	./lib/protocols/l2/
	./lib/logging/
	./lib/raw/
	./src/)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -g -ggdb")

add_library(packet_core ${LIB_SOURCES})

add_executable(fwd ${SERVICE_SOURCES})
target_link_libraries(fwd packet_core jsoncpp)


