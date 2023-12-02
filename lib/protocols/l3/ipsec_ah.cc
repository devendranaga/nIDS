#include <ipv6.h>
#include <ipsec_ah.h>

namespace firewall {

event_description ip_ah_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Parse_Ok;

    p.deserialize(nh);
    p.deserialize(len);

    /**
     * Refer https://datatracker.ietf.org/doc/html/rfc4302
     * 
     * Payload length of 4 words means : 3 32 bit header fileds : nh, len, reserved, spi, seq +
     * 96 bits (3 32 bits) of ICV if its 96 bits in length - 2.
     * 
     * So a value of 0 means 2 - 2, so the minimum length seem 2 * 4 = 8 bytes.
     * 
     * But the nh, len, reserved, spi and seq are always present so the default length
     * is 12 bytes = 3 - 2 = 1 word.
     */
    if (len <= len_)
        return event_description::Evt_IPSec_AH_Inval_Len;

    /**
     * ICV compute length by adding 2 to the total length and subtracting the minimum header length
     * without the ICV.
     */
    icv_len = (len + 2) - IPSEC_AH_LEN_NO_ICV;
    if (icv_len == 0)
        return event_description::Evt_IPSec_AH_Zero_ICV_Len;

    p.deserialize(reserved);
    p.deserialize(ah_spi);
    p.deserialize(ah_seq);

    /**
     * OOB check before memcpy the ICV.
     */
    if (icv_len <= IPSEC_AH_ICV_LEN)
        p.deserialize(ah_icv, icv_len);

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

