project(firewall)

cmake_minimum_required(VERSION 3.22)

SET(LIB_SOURCES_RAW
	./lib/raw/raw_socket.cc)

include_directories(./lib/raw/)

