# Architecture

## Introduction:

nIDS follow a simpler thread based architecture. For each interface available
in the configuration, it creates a thread to receive and parse the frames on
that particular interface.

So there is a dedicated thread per network interface to receive the packets.

Each received frame is then queued to a corresponding parser thread.

After parsing, the parser thread queues to an event manager thread.

Event manager thread queues the frame to a file writer thread or to the network.

So in the system with two NICs we have:

1. 1 main thread
2. 2 interface threads
3. 2 parser threads
4. 1 event manager thread
5. 1 file writer thread

In total there are 7 threads.

The entire packet core uses dynamic memory with managed memory allocators to avoid memory
leaks where possible.

This also means that the allocations are made at the hot-path thus reducing the performance.
The trade-off is that the local stack usage is less thus stopping any stack smashing errors and
hard to debug problems. It also mean that the optional fields can be easily detected by
checking the pointer validity.

So far, I could think of a packet buffer pool for pre-allocation, but this gets complicated
if the packet contains multi level layers or packet contains tunneled frames.

Right now nIDS runs on linux only. May be in the future other OSes are targets.

To test the nIDS, i have written the following tools.

1. Packet generator - This tool can do from replay of PCAPs to generation of frames of any types given a simple configuration.
                      This is a very dangerous tool and must not be used on any network of any scale for damaging purposes.
					  **I AM NOT RESPONSIBLE FOR THE USE OF THIS TOOL ANYWHERE.**
2. controller - controls the nIDS dynamically at runtime or gets various stats and info.
3. Event Reader - Reads event logs from the file.
4. Event Listener - Listens to nIDS events on an MQTT connection and displays them.
					This is another way to grab nIDS events remotely for monitoring and logging purposes.

## Cryptography

So far cryptography is not used on packets. The following frames cannot be validated for their decryption, and integrity.

1. MACsec
2. MKA
3. IPsec
4. TLS
5. DTLS
6. MQTT-secured

This generally means that nIDS cannot do monitoring if the frames are secured. It also mean that this
tool cannot be used for eavesdropping yet.

But, however, cryptography will be used in nIDS for the following purposes.

1. Encryption and Authentication of Event logs.
2. Encryption and Authentication of Event messages.


## Opensource libraries

Following libraries are used / planned to be used.

1. jsoncpp
2. openssl
3. libmosquittopp
4. pahomqtt-c


### Configuration

The following are the configuration files.

1. firewall_config.json - base configuration.
2. rule_config.json - rules file per each interface.
3. packet_gen.json - packet generator configuration.

### Init process

Below are the initialization done by the main thread:

1. The main thread creates and initializes various other threads.
2. The following are done:
	1. Parse configuration
	2. Init the Filters.
	3. For each interface, load rules and initialize a raw socket
	4. Start the read thread for each interface in a loop.
	5. Init the event manager.
3. Main thread sleeps in an infinite loop. This can be replaced with opportunistic sleep.


### Run time:

Packet retrieval is generally done with the use of raw sockets. I can try other means such as eBPF and the likes.
But right now the focus is on filters and rule matching methods.

1. Interface specific thread receives and queues the frame.
2. Another thread listening for the packet, wakes and dequeues.
3. At each dequeue, parsing is done on the frame.
4. After each parsing, the filtering and rule matching must be done. Currently
   this is not done yet.
5. Right now, each packet is matched against a known rules and known vulnerabilities.
6. If a match is found, the packet is denied and subsequently passed to the event manager.
7. If not matched, the packet is deemed ok.

**Memory Usage**

1. Since there could be potential problems with the stack usage (over 8k) and the flexibility of
   running this program on any embedded / ARM based hardware, managed memory is used.
2. Every incoming packet will have 4k of local memory that is on stack. This could as well be moved to use dynamic memory.
3. During the parsing, the `parser` struct uses dynamic memory at each layer.
4. Since dynamic memory is used almost all possible cases, excluding the cases where the data buffer needed.
5. Memory is freed at the destructor to avoid any possible leak.



### Eventing:

1. The event manager runs a thread that wakes up periodically.
2. If the events are queued to it, the following are done:
	1. Queue them to a file writer thread. This will write the events to a file.
	2. File writer can write to the binary format log or to a json format log.
	3. Log to syslog if enabled.

### Filtering process:

1. TBD

### Application of rules:

1. TBD


### Performance:

I have written perf library API to measure performance times using `CLOCK_MONOTONIC`.

The following metrics are of concern to me.

1. Time to perform parsing and filtering.

   On X86 using 1 core and no thread pinning:

	1. The raw parsing and filtering performance so far on a full frame with application payload is 6 microseconds.


