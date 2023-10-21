project(firewall)

cmake_minimum_required(VERSION 3.25)

SET(LIB_SOURCES_L2
	./lib/protocols/l2/eth.cc
	./lib/protocols/l2/arp.cc
	./lib/protocols/l2/ptp.cc
	./lib/protocols/l2/vlan.cc)

include_directories(./lib/protocols/l2/)

