/**
 * @brief - implements IEEE 802.1AE MACsec serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_PROTOCOLS_MACSEC_H__
#define __FW_LIB_PROTOCOLS_MACSEC_H__

#include <cstring>
#include <ether_types.h>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

#define MACSEC_ICV_LEN 16

struct ieee8021ae_tci {
    uint32_t ver:1;
    uint32_t es:1;
    uint32_t sc:1;
    uint32_t scb:1;
    uint32_t e:1;
    uint32_t c:1;
    uint32_t an:2;

    explicit ieee8021ae_tci() :
                    ver(0),
                    es(0),
                    sc(0),
                    scb(0),
                    e(0),
                    c(0),
                    an(0) { }
    ~ieee8021ae_tci() { }
};

struct ieee8021ae_sci {
    uint8_t mac[6];
    uint16_t port_id;

    explicit ieee8021ae_sci()
    {
        std::memset(mac, 0, sizeof(mac));
        port_id = 0;
    }
    ~ieee8021ae_sci() { }
};

/**
 * @brief - implements MACsec serialize and deserialize.
*/
struct ieee8021ae_hdr {
    ieee8021ae_tci tci;
    uint8_t short_len;
    uint32_t pkt_number;
    ieee8021ae_sci sci;
    uint16_t ethertype;
    uint16_t data_len;
    uint8_t *data;
    uint8_t icv[MACSEC_ICV_LEN];

    explicit ieee8021ae_hdr() : data_len(0), data(nullptr)
    {
        std::memset(icv, 0, sizeof(icv));
    }
    ~ieee8021ae_hdr()
    {
        if (data)
            free(data);
    }

    int serialize(packet &p);
    /**
     * @brief - implements ARP deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("IEEE802.1AE: {\n");
        log->verbose("\t tci; {\n");
        log->verbose("\t\t ver: %d\n", tci.ver);
        log->verbose("\t\t es:  %d\n", tci.ver);
        log->verbose("\t\t sc:  %d\n", tci.sc);
        log->verbose("\t\t scb: %d\n", tci.scb);
        log->verbose("\t\t e:   %d\n", tci.e);
        log->verbose("\t\t c:   %d\n", tci.c);
        log->verbose("\t\t an:  %d\n", tci.an);
        log->verbose("\t }\n");
        log->verbose("\t short_len: %d\n", short_len);
        log->verbose("\t pkt_number: %u\n", pkt_number);
        log->verbose("\t sci: {\n");
        log->verbose("\t\t mac: %02x-%02x-%02x-%02x-%02x-%02x\n",
                            sci.mac[0], sci.mac[1],
                            sci.mac[2], sci.mac[3],
                            sci.mac[4], sci.mac[5]);
        log->verbose("\t\t port_number: %u\n", sci.port_id);
        log->verbose("\t }\n");
        if (is_an_authenticated_frame()) {
            log->verbose("\t Ethertype: 0x%04x\n", ethertype);
        }
        log->verbose("\t data_len: %d\n", data_len);
        log->verbose("\t ICV: ");
        for (auto i = 0; i < MACSEC_ICV_LEN; i ++) {
            fprintf(stderr, "%02x ", icv[i]);
        }
        fprintf(stderr, "\n");
        log->verbose("}\n");
    #endif
    }
    bool is_an_encrypted_frame() { return tci.e && tci.c; }
    bool is_an_authenticated_frame() { return (tci.e == 0) && (tci.c == 0); }
    Ether_Type get_ethertype()
    {
        if (is_an_authenticated_frame()) {
            return static_cast<Ether_Type>(ethertype);
        }

        return Ether_Type::Ether_Type_Unknown;
    }

    private:
        int macsec_hdr_len_min_ = 22;
};

}

#endif
