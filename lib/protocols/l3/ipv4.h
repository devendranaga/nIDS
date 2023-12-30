/**
 * @brief - implements ipv4 protocol serialize and deserialize.
 *
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_IPV4_H__
#define __FW_PROTOCOLS_IPV4_H__

#include <stdint.h>
#include <vector>
#include <memory>
#include <logger.h>
#include <packet.h>
#include <protocols_types.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

#define IPV4_VERSION 4
#define IPV4_IHL_LEN 4
#define IPV4_HDR_NO_OPTIONS 20
#define IPV4_HDR_LEN_MAX 60
#define IPV4_MCAST_ADDR_START 224
#define IPV4_MCAST_ADDR_END 239
#define IPV4_RESERVED_ADDR_START 240
#define IPV4_RESERVED_ADDR_END 255
#define IPV4_BROADCAST_ADDR 0xFFFFFFFF

struct ipv6_hdr;

enum class IPv4_Opt {
    End_Of_Options = 0,
    Nop = 1,
    Loose_Source_Route = 3,
    Timestamp = 4,
    Commercial_IP_Security = 6,
    Strict_Source_Route = 9,
    Router_Alert = 20,
};

struct ipv4_opt_comm_sec {
    uint32_t copy_on_frag:1;
    uint32_t cls:2;
    uint8_t len;
    uint32_t doi;
    uint8_t tag_type;
    uint8_t sensitivity_level;

    explicit ipv4_opt_comm_sec(uint32_t copy_on_frag, uint32_t cls) :
                                    copy_on_frag(copy_on_frag),
                                    cls(cls) { }
    ~ipv4_opt_comm_sec() { }
    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
    #endif
    }
};

struct ipv4_opt_ts_data {
    uint32_t ts;
    uint32_t ipaddr;

    explicit ipv4_opt_ts_data() : ts(0), ipaddr(0) { }
    ~ipv4_opt_ts_data() { }
};

/**
 * @brief - implements timestamp option.
*/
struct ipv4_opt_timestamp {
#define IPV4_OPT_FLAG_TS_ONLY 0
#define IPV4_OPT_FLAG_TS_AND_ADDR 1
    uint32_t copy_on_frag:1;
    uint32_t cls:2;
    uint8_t len;
    uint8_t ptr;
    uint32_t overflow:4;
    uint32_t flag:4;
    std::vector<ipv4_opt_ts_data> ts_list;

    explicit ipv4_opt_timestamp() { }
    explicit ipv4_opt_timestamp(uint32_t copy_on_frag, uint32_t cls) :
                                    copy_on_frag(copy_on_frag),
                                    cls(cls) { }
    ~ipv4_opt_timestamp() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\tTimestamp: {\n");
        log->verbose("\t\t\tcopy_on_frag: %d\n", copy_on_frag);
        log->verbose("\t\t\tcls: %d\n", cls);
        log->verbose("\t\t\tlen: %d\n", len);
        log->verbose("\t\t\tptr: %d\n", ptr);
        log->verbose("\t\t\toverflow: %d\n", overflow);
        log->verbose("\t\t\tflag: %d\n", flag);
        for (auto it : ts_list) {
            log->verbose("\t\t\ttimestamp: %u\n", it.ts);
            log->verbose("\t\t\tipaddr: %u\n", it.ipaddr);
        }
        log->verbose("\t\t}\n");
    #endif
    }
};

struct ipv4_opt_router_alert {
    uint32_t copy_on_fragment:1;
    uint32_t cls:2;
    uint8_t len;
    uint16_t router_alert;

    explicit ipv4_opt_router_alert() { }
    explicit ipv4_opt_router_alert(uint32_t cof, uint32_t cls) :
                    copy_on_fragment(cof), cls(cls) { }
    ~ipv4_opt_router_alert() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Router_Alert: {\n");
        log->verbose("\t\t copy_on_fragment: %d\n", copy_on_fragment);
        log->verbose("\t\t cls: %d\n", cls);
        log->verbose("\t\t len: %d\n", len);
        log->verbose("\t\t router_alert: %d\n", router_alert);
        log->verbose("\t }\n");
    #endif
    }
};

struct ipv4_opt_strict_source_route {
    uint32_t copy_on_fragment:1;
    uint32_t cls:2;
    uint8_t len;
    uint8_t pointer;
    uint32_t dest_addr;

    ipv4_opt_strict_source_route(uint32_t copy_on_frag, uint32_t cls) :
                        copy_on_fragment(copy_on_frag), cls(cls) { }
    ~ipv4_opt_strict_source_route() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Strict_Source_Route: {\n");
        log->verbose("\t\t copy_on_fragment: %d\n", copy_on_fragment);
        log->verbose("\t\t cls: %d\n", cls);
        log->verbose("\t\t len: %d\n", len);
        log->verbose("\t\t pointer: %d\n", pointer);
        log->verbose("\t\t dest_addr: %u\n", dest_addr);
        log->verbose("\t }\n");
    #endif
    }

    private:
        const int len_ = 6;
};

struct ipv4_opt_loose_source_route {
    uint32_t copy_on_fragment:1;
    uint32_t cls:2;
    uint8_t len;
    uint8_t pointer;
    uint32_t dest_addr;

    ipv4_opt_loose_source_route(uint32_t copy_on_frag, uint32_t cls) :
                        copy_on_fragment(copy_on_frag), cls(cls) { }
    ~ipv4_opt_loose_source_route() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Loose_Source_Route: {\n");
        log->verbose("\t\t copy_on_fragment: %d\n", copy_on_fragment);
        log->verbose("\t\t cls: %d\n", cls);
        log->verbose("\t\t len: %d\n", len);
        log->verbose("\t\t pointer: %d\n", pointer);
        log->verbose("\t\t dest_addr: %u\n", dest_addr);
        log->verbose("\t }\n");
    #endif
    }
};

/**
 * @brief - parses list of ipv4 options.
*/
struct ipv4_options {
    std::shared_ptr<ipv4_opt_comm_sec> comm_sec;
    std::shared_ptr<ipv4_opt_timestamp> ts;
    std::shared_ptr<ipv4_opt_router_alert> ra;
    std::shared_ptr<ipv4_opt_strict_source_route> ssr;
    std::shared_ptr<ipv4_opt_loose_source_route> lsr;

    explicit ipv4_options() :
                    comm_sec(nullptr),
                    ts(nullptr),
                    ra(nullptr),
                    ssr(nullptr),
                    lsr(nullptr) { }
    ~ipv4_options() { }

    event_description deserialize(packet &p, logger *log, uint32_t opt_len, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        if (comm_sec)
            comm_sec->print(log);
        if (ts)
            ts->print(log);
        if (ra)
            ra->print(log);
        if (ssr)
            ssr->print(log);
        if (lsr)
            lsr->print(log);
    #endif
    }
};

/**
 * @brief - Implements IPv4 header serialize and deserialize.
*/
struct ipv4_hdr {
    uint8_t version;
    uint32_t hdr_len;
    uint32_t dscp;
    uint32_t ecn;
    uint16_t total_len;
    uint16_t identification;
    bool reserved;
    bool dont_frag;
    bool more_frag;
    uint32_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_chksum;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t start_off;
    uint32_t end_off;

    ipv4_options opt;

    //
    // ip in ip
    std::shared_ptr<ipv4_hdr> ipip;

    //
    // 6 in 4
    std::shared_ptr<ipv6_hdr> ipv6_in_ipv4;

    protocols_types get_protocol() const noexcept;

    explicit ipv4_hdr() :
                start_off(0),
                end_off(0) { }
    ~ipv4_hdr() { }

    /**
     * @brief - check if an ipv4 packet is a fragment.
     *
     * @return true if a fragment
     * @return false if not
    */
    bool is_a_frag() { return (frag_off > 0) || more_frag; }

    /**
     * @brief - serialize the ipv4 packet.
     * 
     * @param [in] p - packet
     * 
     * @return 0 on success -1 on failure.
    */
    int serialize(packet &p);

    /**
     * @brief - deserialize the ipv4 packet.
     *
     * @param [inout] p - packet
     * @param [in] log - logger
     * @param [in] debug - debug print
     * 
     * @return returns the event description after parsing the frame.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);

    /**
     * @brief - prints the ipv4 header
     *
     * @param [in] log - logger.
     */
    void print(logger *log);

    /**
     * @brief - validate the checksum.
     *
     * @return true if checksum is valid
     * @return false if checksum is invalid
    */
    bool validate_checksum(packet &p);

    /**
     * @brief - get the ipv4 address in string format.
     *
     * @param [in] ipaddr - ipaddr in uint32_t
     * @param [out] ipaddr_str - output ipaddr in string format
     */
    void get_ipaddr_str(uint32_t ipaddr, std::string &ipaddr_str);

    /**
     * @brief - generate the ipv4 checksum
     *
     * @param [in] p - input frame
     *
     * return computed checksum
     */
    uint16_t generate_checksum(packet &p);

    inline bool is_dst_multicast()
    {
        return is_multicast(dst_addr);
    }

    inline bool is_src_multicast()
    {
        return is_multicast(src_addr);
    }

    inline bool is_dst_broadcast()
    {
        return is_broadcast(dst_addr);
    }

    inline bool is_src_broadcast()
    {
        return is_broadcast(src_addr);
    }

    inline bool is_src_reserved()
    {
        return is_reserved(src_addr);
    }

    inline bool is_dst_reserved()
    {
        return is_reserved(dst_addr);
    }

    inline bool is_dst_loopback()
    {
        return is_loopback(dst_addr);
    }

    inline bool is_src_loopback()
    {
        return is_loopback(src_addr);
    }

    inline bool is_dst_directed_broadcast()
    {
        return is_directed_broadcat(dst_addr);
    }

    inline bool is_src_directed_broadcast()
    {
        return is_directed_broadcat(src_addr);
    }

    private:
    inline bool is_multicast(uint32_t ip_addr)
    {
        uint32_t byte = (ip_addr & 0xFF000000) >> 24;

        if ((byte >= IPV4_MCAST_ADDR_START) && (byte <= IPV4_MCAST_ADDR_END))
            return true;

        return false;
    }

    inline bool is_reserved(uint32_t ip_addr)
    {
        uint32_t byte = (ip_addr & 0xFF000000) >> 24;

        if ((byte >= IPV4_RESERVED_ADDR_START) && (byte <= IPV4_RESERVED_ADDR_END))
            return true;

        return false;
    }

    inline bool is_broadcast(uint32_t ipaddr)
    {
        return ipaddr == 0xFFFFFFFF;
    }

    inline bool is_loopback(uint32_t ipaddr)
    {
        uint32_t byte = (ipaddr & 0xFF000000) >> 24;

        return (byte == 0x7F);
    }

    //
    // sometimes this is not the only directed broadcast
    // address. It depends on the network mask / subnet mask.
    //
    // for a subnetwork of 13 bits, we could have the network
    // between 1 - 30. 31 could be the broadcast address.
    inline bool is_directed_broadcat(uint32_t ipaddr)
    {
        uint32_t byte = (ipaddr & 0x000000FF);

        return (byte == 0xFF);
    }

};

}

#endif
