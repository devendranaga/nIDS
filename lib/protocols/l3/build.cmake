project(firewall)
cmake_minimum_required(VERSION 3.25)

SET(LIB_SOURCES_L3
	./lib/protocols/l3/ipv4.cc
	./lib/protocols/l3/ipv6.cc)

include_directories(./lib/protocols/l3/)

