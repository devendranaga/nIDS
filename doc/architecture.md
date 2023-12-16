# Architecture

## Introduction:

nIDS follow a simpler thread based architecture. For each interface available
in the configuration, it creates a thread to receive and one thread to parse the frames on
that particular interface. Each filter may have a dedicated thread to perform filtering.

So there is a dedicated thread per network interface to receive the packets.

Each received frame is then queued to a corresponding parser thread.

After parsing, corresponding filters are called upon.
After done, The parser thread queues to an event manager thread.

Event manager thread queues the frame to a file writer thread or to the network.

So in the system with two NICs we have:

1. 2 interface threads (1 for each NIC)
2. 2 pcap log threads (1 for each NIC)
3. 2 parser threads (1 for each NIC)

In general we have global threads:

1. 1 main thread
2. 1 event manager thread
3. 1 file writer thread
4. 1 front end interface thread for servicing stats

The interface and network threads scale with number of input interfaces to filter on.

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

The following are the configuration files. All the configuration follow json format for readability.

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

Right now, no thread pinning has been used so far.

### Run time:

Packet retrieval is generally done with the use of raw sockets. For parsing, I can try other means such as eBPF and the likes.
But right now the focus is on filters and rule matching methods.

1. Interface specific thread receives and queues the frame.
2. Another thread listening for the packet, wakes and dequeues.
3. At each dequeue, parsing is done on the frame.
4. After each parsing, the filtering and rule matching must be done. Currently
   this is done only for few specific filters.
5. Each packet is matched against a known rules and known vulnerabilities.
6. If a match is found, the packet is denied and subsequently passed to the event manager.
7. If not matched, the packet is deemed ok. It is then passed across all the possible
   filters that can be applied on it.
8. An example is that for a typical ICMP, rules matching for its ethertype, ip header and ICMP
   will be checked if they are present in the configuration.
9. If no rule is matched, we are simply allowing the frame. But we are not eventing it, this needs to be done.

**Memory Usage**

1. Since there could be potential problems with the stack usage (over 8k) and the flexibility of
   running this program on any embedded / ARM based hardware, managed memory is used.
2. Every incoming packet will have 4k of local memory that is on stack. This could as well be moved to use dynamic memory.
3. During the parsing, the `parser` struct uses dynamic memory at each layer.
4. Since dynamic memory is used almost all possible cases, excluding the cases where the data buffer needed.
5. Memory is freed at the destructor to avoid any possible leak.

### Queueing

Queueing is most used in the nIDS.

Following types are being queued:

1. Incoming frame
2. Parsed packet
3. Events

Every incoming frame gets queued into two main places.

1. For parser for parsing and filtering.
2. For logging in pcap.

Parsed packet is queued into the event manager for the following:

1. Perform specific filtering - icmp, arp are few instances
2. writing events to a file
3. writing events to a mqtt
4. writing events to a console or syslog

Events are queued only for forwarding:

1. forward via mqtt to a remote host.

Queueing generally introduce delay, but the threads process each frame in parallel to avoid
packet loss or more time being spent in receive path leading to starvation of incoming frames.

### Eventing:

1. The event manager runs a thread that wakes up periodically.
2. If the events are queued to it, the following are done:
	1. Queue them to a file writer thread. This will write the events to a file.
	2. File writer can write to the binary format log or to a json format log.
	3. Log to syslog if enabled.

### Filtering process:

The filtering architecture is really fragmented. I need to think about it deeply.

1. After parser entirely dissects the input packet and runs through the malware analysis filters,
   it then calls filter function.
2. The filter function runs in a loop of all available configured rules, matching the input
   packet to their signatures.
3. I maintain two separate structures with bit fields:

      1. Available_signatures from the config
      2. Detected_signatures so far

4. Once both the structures match, the corresponding rule is matched.
5. Check the rule-type : allow, deny or event and take corresponding action.


### Performance:

I have written perf library API to measure performance times using `CLOCK_MONOTONIC`.

The following metrics are of concern to me.

1. Time to perform parsing and filtering.

   On X86 using 1 core and no thread pinning:

	1. The raw parsing and filtering performance so far on a full frame with application payload is 6 microseconds.

2. A flood ping at 1 usec inter packet gap really tested the ICMP filter capability.

   On an average, the filter latency was around 6 microseconds with some debug prints. However, the flood ping
   was really testing the queues and parser speed to deque and process. Right now, i do not have a solution
   for this high rate of flood input to parse and figure. No plans to think about it too, because a flood at
   such a high rate is generally a cause of DoS and i must rather focus on writing a DoS filter at the moment
   to drop frames at the Receiver thread itself.


