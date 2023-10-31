#ifndef __FW_EVENT_EVENT_FILE_WRITER_HDR_H__
#define __FW_EVENT_EVENT_FILE_WRITER_HDR_H__

#include <stdint.h>

namespace firewall {

enum class Hash_Algorithm {
    None,
    SHA2,
};

enum class Encryption_Algorithm {
    None,
    AES_CTR_128,
};

struct event_file_hdr {
#define EVT_FILE_VERSION 1
    uint8_t version;
    Hash_Algorithm hash_alg;
    Encryption_Algorithm enc_alg;
    uint32_t enc_msg_len;
    uint32_t hash_len;
    uint8_t iv[16];
    uint8_t hash[64];
} __attribute__ ((__packed__));

}

#endif
