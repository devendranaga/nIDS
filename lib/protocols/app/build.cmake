project(firewall)
cmake_minimum_required(VERSION 3.25)

SET(LIB_SOURCES_APP
	./lib/protocols/app/dhcp.cc
	./lib/protocols/app/ntp.cc)

include_directories(./lib/protocols/app/)

