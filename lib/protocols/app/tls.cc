/**
 * @brief - Implements TLS serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <tls.h>

namespace firewall {

int tls_hdr::serialize(packet &p)
{
    return -1;
}

event_description tls_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte_1 = 0;
    uint8_t byte_2[2] = {0, 0};

    p.deserialize(byte_1);
    type = static_cast<Content_Type>(byte_1);

    p.deserialize(byte_2, sizeof(byte_2));
    if ((byte_2[0] == 0x03) && (byte_2[1] == 0x01)) {
        version = Tls_Version::Tls_Version_1_0;
    } else if ((byte_2[0] == 0x03) && (byte_2[1] == 0x02)) {
        version = Tls_Version::Tls_Version_1_1;
    } else if ((byte_2[0] == 0x03) && (byte_2[1] == 0x03)) {
        version = Tls_Version::Tls_Version_1_2;
    } else {
        return event_description::Evt_TLS_Version_Unsupported;
    }

    return event_description::Evt_Parse_Ok;
}

}
