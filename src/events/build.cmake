project(firewall)
cmake_minimum_required(VERSION 3.22)

SET(EVENT_MGR_SOURCES
	./src/events/event_mgr.cc
	./src/events/event_file_writer.cc)

include_directories(./src/events/)

