project(firewall)
cmake_minimum_required(VERSION 3.22)

SET(LIB_SOURCES_LOGGING
	./lib/logging/logger.cc)

include_directories(./lib/logging/)

