/**
 * @brief - Implements packet structure.
 *
 * @copyright - All rights reserved. Devendra Naga.
 */
#ifndef __FW_PACKET_H__
#define __FW_PACKET_H__

#include <iostream>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <common.h>

namespace firewall {

struct packet {
    uint8_t *buf;
    uint32_t buf_len;
    uint32_t off;

    explicit packet();
    explicit packet(uint32_t pkt_len);
    int create(uint8_t *pkt, uint32_t buf_len);
    void free_pkt();
    ~packet();

    fw_error_type serialize(uint8_t byte);
    fw_error_type serialize(uint16_t bytes);
    fw_error_type serialize(uint32_t bytes);
    fw_error_type serialize(uint8_t *mac);
    fw_error_type deserialize(uint8_t &byte);
    fw_error_type deserialize(uint16_t &bytes);
    fw_error_type deserialize(uint32_t &bytes);
    fw_error_type deserialize(uint8_t *mac);
};

}

#endif

