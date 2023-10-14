# Firewall

This is an implementation of firewalling for Linux based routers and switches.

This is implemented with C++17 language standard and some shell script.

## Pre-requisites

This project uses cmake for build and jsoncpp for configuration parsing.

```bash
sudo apt install cmake libjsoncpp-dev
```

## Compiling

```bash
mkdir build
cd build
cmake ../
make -j12
```

Supported protocols are [here](doc/supported_protocols.md).

Supported signatures are [here](doc/supported_signatures.md).
