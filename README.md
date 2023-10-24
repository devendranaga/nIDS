# Firewall

This is an implementation of firewalling for Linux based routers and switches.

This is implemented with C++17 language standard and some shell script.

**Note**

This service have not been tested on all possible packets and hardware. Use it at your own risk!

## Pre-requisites

This project uses cmake for build and jsoncpp for configuration parsing.

```bash
sudo apt install cmake libjsoncpp-dev
```

## Build macros

Fllowing are the build macros used in the nIDS.

| S. No | Macro name | Description |
|-------|------------|-------------|
| 1 |  DFW_ENABLE_DEBUG | Enable debugging |


## Compiling

```bash
mkdir build
cd build
cmake ../
make -j12
```

## Supported Protocols

Supported protocols are [here](doc/supported_protocols.md).

## Supported signatures

Supported signatures are [here](doc/supported_signatures.md).


