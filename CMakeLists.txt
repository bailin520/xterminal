cmake_minimum_required (VERSION 2.6)

project(xterminal C)

#set(CMAKE_VERBOSE_MAKEFILE ON)

add_definitions(-O -Wall -Werror --std=gnu99 -g3)
add_definitions(-DMG_ENABLE_HTTP_STREAMING_MULTIPART)
add_definitions(-DMG_ENABLE_SSL)

add_executable(xterminal_broker xterminal_broker.c)
target_link_libraries(xterminal_broker evmongoose ev)

add_executable(xterminal_device xterminal_device.c)
target_link_libraries(xterminal_device evmongoose ev)