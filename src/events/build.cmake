project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB EVENT_MGR_SOURCES ${PROJECT_SOURCE_DIR}/src/events/*.cc)
include_directories(./src/events/)

