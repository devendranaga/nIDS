project(firewall)
cmake_minimum_required(VERSION 3.25)

set(LIB_SOURCES
	./lib/packet.cc
	./lib/protocols/l2/eth.cc)

include_directories(
	./lib
	./lib/protocols/l2/)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter")

add_library(packet_core ${LIB_SOURCES})

