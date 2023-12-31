/**
 * @brief - Implements IGMP serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_PROTOCOLS_L4_IGMP_H__
#define __FW_LIB_PROTOCOLS_L4_IGMP_H__

#include <vector>
#include <memory>
#include <packet.h>
#include <event_def.h>
#include <logger.h>
#include <common.h>

namespace firewall {

enum class Igmp_Type {
    Membership_Query = 0x11,
    Membership_Report_V1 = 0x12,
    Membership_Report_V2 = 0x16,
    Membership_Report_V3 = 0x22,
    Leave_Group = 0x17,
};

struct igmp_leave_group {
    uint32_t mcast_addr;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t LeaveGroup: {\n");
        log->verbose("\t\t mcast_addr: %u\n", mcast_addr);
        log->verbose("\t }\n");
    #endif
    }
};

struct igmp_membership_query {
    uint32_t mcast_addr;
    uint32_t router_side_processing:1;
    uint32_t qrv;
    uint8_t qqic;
    uint16_t n_src;

    explicit igmp_membership_query() :
                    mcast_addr(0),
                    router_side_processing(0),
                    qrv(0),
                    qqic(0),
                    n_src(0) { }
    ~igmp_membership_query() { }

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
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        std::string ipaddr_str;

        log->verbose("\t Membership Query: {\n");

        get_ipaddr(mcast_addr, ipaddr_str);
        log->verbose("\t\t mcast_addr: %u\n", ipaddr_str.c_str());
        log->verbose("\t\t router_side_processing: %d\n", router_side_processing);
        log->verbose("\t\t qrv: %d\n", qrv);
        log->verbose("\t\t qqic: %d\n", qqic);
        log->verbose("\t\t n_src: %d\n", n_src);
        log->verbose("\t }\n");
    #endif
    }
};

enum Igmp_Group_Record_Type {
    Exclude = 2,
    Change_To_Exclude_Mode = 4,
};

struct igmp_group_record {
    //
    // Igmp_Group_Record_Type
    uint8_t type;
    uint8_t aux_data_len;
    uint16_t num_src;
    uint32_t mcast_addr;

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t Group Record: {\n");
        log->verbose("\t\t\t type: %d\n", type);
        log->verbose("\t\t\t aux_data_len: %d\n", aux_data_len);
        log->verbose("\t\t\t num_src: %d\n", num_src);
        log->verbose("\t\t\t mcast_addr: %u\n", mcast_addr);
        log->verbose("\t\t }\n");
    #endif
    }
};

struct igmp_membership_report_v2 {
    int serialize(packet &p);
};

/**
 * @brief - Implements Membership Report V3.
 */
struct igmp_membership_report {
    uint16_t reserved;
    uint16_t num_groups;
    std::vector<igmp_group_record> rec_list_;

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
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Membership Report: {\n");
        log->verbose("\t\t reserved: %d\n", reserved);
        log->verbose("\t\t num_groups: %d\n", num_groups);
        for (auto it : rec_list_) {
            it.print(log);
        }
        log->verbose("\t }\n");
    #endif
    }
};

struct igmp_hdr {
    uint8_t type;
    uint8_t max_resp_time; // 10ths of a second
    uint16_t checksum;

    std::shared_ptr<igmp_membership_query> mem_query;
    std::shared_ptr<igmp_membership_report> mem_report;
    std::shared_ptr<igmp_leave_group> leave_group;

    explicit igmp_hdr() :
                type(0),
                max_resp_time(0),
                checksum(0),
                mem_query(nullptr),
                mem_report(nullptr),
                leave_group(nullptr)
    { }
    ~igmp_hdr() { }

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
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("IGMP header: {\n");
        log->verbose("\t type: 0x%02x\n", type);
        log->verbose("\t max_resp_time: %d\n", max_resp_time);
        log->verbose("\t checksum: 0x%04x\n", checksum);

        if (mem_query)
            mem_query->print(log);

        if (mem_report)
            mem_report->print(log);

        if (leave_group)
            leave_group->print(log);

        log->verbose("}\n");
    #endif
    }

    private:
        int hdr_len_ = 4;
};

}

#endif
