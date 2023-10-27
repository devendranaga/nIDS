/**
 * @brief - implements NTP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <ntp.h>

namespace firewall {

int ntp_hdr::serialize(packet &p)
{
    return -1;
}

event_description ntp_hdr::deserialize(packet &p, logger *log, bool debug)
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

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void ntp_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("NTP: {\n");
    log->verbose("\tleap_indicator: %d\n", leap_indicator);
    log->verbose("\tversion: %d\n", version);
    log->verbose("\tmode: %d\n", mode);
    log->verbose("\tpeer_clock_stratum: %u\n", peer_clock_stratum);
    log->verbose("\tpeer_polling_intvl: %u\n", peer_polling_intvl);
    log->verbose("\tpeer_clock_precision: %u\n", peer_clock_precision);
    log->verbose("\troot_delay_intvl_sec: %u\n", root_delay_intvl_sec);
    log->verbose("\troot_dispersion: %u\n", root_dispersion);
    log->verbose("\treference_id: %u\n", reference_id);
    log->verbose("\treference_timestamp: %u\n", reference_timestamp);
    log->verbose("\torigin_timestamp: %u\n", origin_timestamp);
    log->verbose("\treceive_timesatmp: %u\n", receive_timestamp);
    log->verbose("\ttransmit_timestamp: %u\n", transmit_timestamp);
    log->verbose("}\n");
#endif
}

}

