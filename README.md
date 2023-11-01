# Firewall (nIDS)

This is an implementation of firewalling for Linux based routers and switches.

This is implemented with C++17 language standard and some shell script.

The nIDS detection is performed at various levels of the TCP/IP stack and also in the
application level performing DPI (Deep Packet Inspection).

**Note**

This service have not been tested on all possible packets and hardware. Use it at your own risk!

## Pre-requisites

This project uses the following:

1. cmake for build
2. jsoncpp for configuration parsing
3. openssl for AES and Hash operations
4. pahomqtt for MQTT publish and subscribers

```bash
sudo apt install cmake libjsoncpp-dev libpaho-mqtt-dev libssl-dev
```

## Build macros

Fllowing are the build macros used in the nIDS.

| S. No | Macro name | Description |
|-------|------------|-------------|
| 1 |  `FW_ENABLE_DEBUG` | Enable debugging |


## Compiling

```bash
mkdir build
cd build
cmake ../
make -j12
```

## Running

### Generating Encryption key

For encryption feature in event logging and MQTT eventing, one needs the encryption key.

```bash
openssl rand -out aes_key.bin 16
```

### Running the services and tools

1. Firewall daemon can be started the following way:

```bash
sudo ./fwd -f firewall_config.json
```

The supporting rules files must be present as well.

2. Packet generator can be started the following way:

```bash
sudo ./packet_gen -f packet_gen.json
```

3. Run fw_ctl to listen for the events:

```bash
./fw_ctl -m 127.0.0.1:1883 -t /nids/events -d aes_key.bin
```

## Supported Protocols

Supported protocols are [here](doc/supported_protocols.md).

## Supported signatures

The nIDS auto detects some of the known malformed packets at various levels of the TCP/IP stack and
known worms. The list is below.

Supported signatures are [here](doc/supported_signatures.md).


