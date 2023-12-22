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

    if (version == 3) {
        p.deserialize(v.v3_hdr.peer_clock_stratum);
        p.deserialize(v.v3_hdr.peer_polling_intvl);
        p.deserialize(v.v3_hdr.peer_clock_precision);
        p.deserialize(v.v3_hdr.root_delay_intvl_sec);
        p.deserialize(v.v3_hdr.root_dispersion);
        p.deserialize(v.v3_hdr.reference_id);
        p.deserialize(v.v3_hdr.reference_timestamp);
        p.deserialize(v.v3_hdr.origin_timestamp);
        p.deserialize(v.v3_hdr.receive_timestamp);
        p.deserialize(v.v3_hdr.transmit_timestamp);
    }

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
    if (version == 3) {
        log->verbose("\tpeer_clock_stratum: %u\n", v.v3_hdr.peer_clock_stratum);
        log->verbose("\tpeer_polling_intvl: %u\n", v.v3_hdr.peer_polling_intvl);
        log->verbose("\tpeer_clock_precision: %u\n", v.v3_hdr.peer_clock_precision);
        log->verbose("\troot_delay_intvl_sec: %u\n", v.v3_hdr.root_delay_intvl_sec);
        log->verbose("\troot_dispersion: %u\n", v.v3_hdr.root_dispersion);
        log->verbose("\treference_id: %u\n", v.v3_hdr.reference_id);
        log->verbose("\treference_timestamp: %u\n", v.v3_hdr.reference_timestamp);
        log->verbose("\torigin_timestamp: %u\n", v.v3_hdr.origin_timestamp);
        log->verbose("\treceive_timesatmp: %u\n", v.v3_hdr.receive_timestamp);
        log->verbose("\ttransmit_timestamp: %u\n", v.v3_hdr.transmit_timestamp);
    }
    log->verbose("}\n");
#endif
}

}

