#include <ipv6.h>
#include <ip_ah.h>

namespace firewall {

event_description ip_ah_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Parse_Ok;

    p.deserialize(nh);
    p.deserialize(len);
    p.deserialize(reserved);
    p.deserialize(ah_spi);
    p.deserialize(ah_seq);
    p.deserialize(ah_icv, IP_AH_ICV_LEN);

    return evt_desc;
}

void ip_ah_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t IP-AH: {\n");
    log->verbose("\t\t next_hdr: %d\n", nh);
    log->verbose("\t\t len: %d\n", len);
    log->verbose("\t\t reserved: %d\n", reserved);
    log->verbose("\t\t ah_spi 0x%x\n", ah_spi);
    log->verbose("\t\t ah_seq: %d\n", ah_seq);
    log->verbose("\t\t ah_icv: %02x %02x %02x %02x %02x %02x "
                              "%02x %02x %02x %02x %02x %02x\n",
                              ah_icv[0], ah_icv[1], ah_icv[2], ah_icv[3],
                              ah_icv[4], ah_icv[5], ah_icv[6], ah_icv[7],
                              ah_icv[8], ah_icv[9], ah_icv[10], ah_icv[11]);
    log->verbose("\t }\n");
#endif
}

}

