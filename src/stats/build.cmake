project(firewall)
cmake_minimum_required(VERSION 3.22)

SET(STATS_SOURCES
	./src/stats/packet_stats.cc)

include_directories(./src/stats/)

