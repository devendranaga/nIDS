project(firewall)
cmake_minimum_required(VERSION 3.22)

SET(CORE_SOURCES
	./src/core/core.cc
	./src/core/rule_parser.cc)

include_directories(./src/core/)

