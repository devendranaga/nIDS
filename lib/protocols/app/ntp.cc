/**
 * @brief - implements NTP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <ntp.h>

namespace firewall {

int ntp::serialize(packet &p)
{
    return -1;
}

event_description ntp::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte_1;

    p.deserialize(byte_1);

    leap_indicator = (byte_1 & 0xC0) >> 6;
    version = (byte_1 & 38) >> 3;
    mode = (byte_1 & 0x07);

    p.deserialize(peer_clock_stratum);
    p.deserialize(peer_polling_intvl);
    p.deserialize(peer_clock_precision);
    p.deserialize(root_delay_intvl_sec);
    p.deserialize(root_dispersion);
    p.deserialize(reference_id);
    p.deserialize(reference_timestamp);
    p.deserialize(origin_timestamp);
    p.deserialize(receive_timestamp);
    p.deserialize(transmit_timestamp);

    return event_description::Evt_Parse_Ok;
}

}

