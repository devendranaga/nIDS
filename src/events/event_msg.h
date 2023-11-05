/**
 * @brief - implements event message format.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_EVENT_MSG_H__
#define __FW_EVENT_MSG_H__

#include <stdint.h>
#include <event_def.h>

namespace firewall {

struct event_udp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t data_len;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct event_tcp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t syn:1;
    uint32_t ack:1;
    uint32_t fin:1;
    uint32_t psh:1;
    uint16_t data_len;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct event_ipv4_info {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t ttl;
    uint32_t protocol;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct event_msg {
    uint32_t rule_id;
    event_type evt_type;
    event_description evt_desc;
    uint32_t ethertype;
    uint8_t data[0];
} __attribute__ ((__packed__));

enum class Hash_Algorithm {
    None,
    SHA2,
};

enum class Encryption_Algorithm {
    None,
    AES_CTR_128,
};

/**
 * @brief - A high level header for the event message.
 */
struct event_msg_hdr {
#define EVT_FILE_VERSION 1
    //
    // Version of the event message
    uint8_t version;
    //
    // hash algorithm type
    Hash_Algorithm hash_alg;
    //
    // encryption algorithm type
    Encryption_Algorithm enc_alg;
    //
    // length of the encrypted message
    uint32_t enc_msg_len;
    //
    // length of the hash - 16, 32, 64
    uint32_t hash_len;
    //
    // IV - for the encryption
    uint8_t iv[16];
    //
    // hash value
    uint8_t hash[64];
} __attribute__ ((__packed__));

}

#endif

