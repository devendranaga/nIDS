project(firewall)
cmake_minimum_required(VERSION 3.25)

SET(PKT_GEN_SOURCES
	./tools/packet_gen/packet_gen_config.cc
	./tools/packet_gen/packet_gen.cc)

include_directories(./tools/packet_gen/)

