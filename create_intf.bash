#!/bin/bash
#

sudo ip link add dummy0 type dummy
sudo ifconfig dummy0 up

sudo ip link add dummy1 type dummy
sudo ifconfig dummy1 up

