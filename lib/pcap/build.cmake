project(firewall)
cmake_minimum_required(VERSION 3.25)

SET(LIB_SOURCES_PCAP
	./lib/pcap/pcap_intf.cc
	./lib/pcap/pcap_replay.cc)

include_directories(./lib/pcap/)

