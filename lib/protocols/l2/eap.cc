#include <eap.h>

namespace firewall {

event_description eap_hdr::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(code);
    p.deserialize(id);
    p.deserialize(len);
    p.deserialize(type);

    return event_description::Evt_Parse_Ok;
}

event_description ieee8021x_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

    p.deserialize(version);
    p.deserialize(type);
    p.deserialize(len);

    switch (static_cast<IEEE8021x_Type>(type)) {
        case IEEE8021x_Type::EAP: {
            eap_h = std::shared_ptr<eap_hdr>();
            if (!eap_h)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = eap_h->deserialize(p, log, debug);
        } break;
        default:
            evt_desc = event_description::Evt_EAP_Type_Unsupported;
    }

    if (debug)
        print(log);

    return evt_desc;
}

}
