project(firewall)
cmake_minimum_required(VERSION 3.25)

SET(LIB_SOURCES_L4
	./lib/protocols/l4/udp.cc
	./lib/protocols/l4/tcp.cc
	./lib/protocols/l4/icmp6.cc
	./lib/protocols/l4/icmp.cc)

include_directories(./lib/protocols/l4/)

