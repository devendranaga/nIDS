/**
 * @brief - Implements packet structure.
 *
 * @copyright - All rights reserved. Devendra Naga.
 */
#ifndef __FW_PACKET_H__
#define __FW_PACKET_H__

#include <iostream>
#include <cstring>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <common.h>

namespace firewall {

struct packet {
    uint8_t buf[4096];
    uint32_t buf_len;
    uint32_t off;

    explicit packet();
    explicit packet(uint32_t pkt_len);
    int remaining_len() { return buf_len - off; }
    ~packet();

    fw_error_type serialize(uint8_t byte);
    fw_error_type serialize(uint16_t bytes);
    fw_error_type serialize(uint32_t bytes);
    fw_error_type serialize(uint64_t bytes);
    fw_error_type serialize(uint8_t *mac);
    fw_error_type serialize(uint8_t *buf, uint32_t buf_len);
    fw_error_type deserialize(uint8_t &byte);
    fw_error_type deserialize(uint16_t &bytes);
    fw_error_type deserialize(uint32_t &bytes);
    fw_error_type deserialize(uint64_t &bytes);
    fw_error_type deserialize(uint8_t *mac);
    fw_error_type deserialize(uint8_t *buf, uint32_t buf_len);
    fw_error_type deserialize(std::vector<uint8_t> &buf, uint32_t buf_len);
    fw_error_type deserialize(std::vector<char> &buf, uint32_t buf_len);
    void hexdump()
    {
        uint32_t i;

        for (i = 0; i < buf_len; i ++) {
            printf("%02x ", buf[i]);
        }
        printf("\n");
    }
};

}

#endif

