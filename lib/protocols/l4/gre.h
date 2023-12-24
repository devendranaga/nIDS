#ifndef __FW_LIB_PROTOCOLS_L4_GRE_H__
#define __FW_LIB_PROTOCOLS_L4_GRE_H__

#include <memory>
#include <logger.h>
#include <event_def.h>
#include <packet.h>
#include <ether_types.h>

namespace firewall {

struct ipv4_hdr;

struct gre_flags {
    uint32_t checksum_bit:1;
    uint32_t routing_bit:1;
    uint32_t key_bit:1;
    uint32_t seq_no:1;
    uint32_t ssr:1;
    uint32_t recursion_control:3;
    uint32_t flags:5;
    uint32_t version:3;
};

struct gre_hdr {
    gre_flags flags;
    Ether_Type protocol;

    std::shared_ptr<ipv4_hdr> ipv4_h;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("GRE: {\n");
        log->verbose("\tflags: {\n");
        log->verbose("\t\tchecksum_bit: %d\n", flags.checksum_bit);
        log->verbose("\t\trouting_bit: %d\n", flags.routing_bit);
        log->verbose("\t\tkey_bit: %d\n", flags.key_bit);
        log->verbose("\t\tseq_no: %d\n", flags.seq_no);
        log->verbose("\t\tssr: %d\n", flags.ssr);
        log->verbose("\t\trecursion_control: %d\n", flags.recursion_control);
        log->verbose("\t\tflags: %d\n", flags.flags);
        log->verbose("\t\tversion: %d\n", flags.version);
        log->verbose("\t}\n");
        log->verbose("\tprotocol: 0x%04x\n", protocol);
        log->verbose("}\n");
    #endif
    }

    private:
        const int min_hdr_len_ = 4;
};

}

#endif

