/**
 * @brief - implements UDS serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#if defined(FW_ENABLE_AUTOMOTIVE)

#include <uds.h>

namespace firewall {

event_description uds_hdr::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(service_id);
    is_reply = !!(service_id & 0x40);

    switch (static_cast<Diag_Service_Id>(service_id)) {
        case Diag_Service_Id::Diag_Sess_Control: {
            p.deserialize(sess_control.type);
            if (is_reply) {
                p.deserialize(sess_control.parameter_rec);
            }
        } break;
        case Diag_Service_Id::Error: {
            p.deserialize(error.service_id);
            p.deserialize(error.code);
        } break;
        default:
            return event_description::Evt_Uds_Unknown_Service_Id;
        break;
    }

    return event_description::Evt_Parse_Ok;
}

}

#endif
