#include <igmp.h>

namespace firewall {

event_description igmp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

    //
    // too short header length
    if (p.remaining_len() < hdr_len_)
        return event_description::Evt_Igmp_Hdr_Len_Too_Small;

    p.deserialize(type);
    p.deserialize(max_resp_time);
    p.deserialize(checksum);

    switch (static_cast<Igmp_Type>(type)) {
        case Igmp_Type::Membership_Query: {
            mem_query = std::make_shared<igmp_membership_query>();
            if (!mem_query)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = mem_query->deserialize(p, log, debug);
        } break;
        case Igmp_Type::Membership_Report_V3: {
            mem_report = std::make_shared<igmp_membership_report>();
            if (!mem_report)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = mem_report->deserialize(p, log, debug);
        } break;
        case Igmp_Type::Leave_Group: {
            leave_group = std::make_shared<igmp_leave_group>();
            if (!leave_group)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = leave_group->deserialize(p, log, debug);
        } break;
        default:
            return event_description::Evt_Igmp_Unsupported_Type;
    }

    if (debug)
        print(log);

    return evt_desc;
}

event_description
igmp_membership_query::deserialize(packet &p,
                                   logger *log, bool debug)
{
    uint8_t byte = 0;

    p.deserialize(mcast_addr);
    p.deserialize(byte);

    router_side_processing = !!(byte & 0x08);
    qrv = (byte & 0x07);

    p.deserialize(qqic);
    p.deserialize(n_src);

    return event_description::Evt_Parse_Ok;
}

event_description
igmp_membership_report::deserialize(packet &p,
                                    logger *log, bool debug)
{
    int i;

    p.deserialize(reserved);
    p.deserialize(num_groups);

    for (i = 0; i < num_groups; i ++) {
        igmp_group_record rec;

        p.deserialize(rec.type);
        p.deserialize(rec.aux_data_len);
        p.deserialize(rec.num_src);
        p.deserialize(rec.mcast_addr);

        rec_list_.emplace_back(rec);
    }

    return event_description::Evt_Parse_Ok;
}

event_description
igmp_leave_group::deserialize(packet &p,
                              logger *log, bool debug)
{
    p.deserialize(mcast_addr);

    return event_description::Evt_Parse_Ok;
}

}
