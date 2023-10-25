/**
 * @brief - Implements packet manipulation routines.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <packet.h>

namespace firewall {

packet::packet()
{
	std::memset(buf, 0, sizeof(buf));
    buf_len = 0;
    off = 0;
}

packet::packet(uint32_t pkt_len) : buf_len(pkt_len), off(0)
{
}

packet::~packet()
{
}

static inline bool packet_assert_length(int in_bytes, int given_len)
{
    return (in_bytes > given_len);
}

fw_error_type packet::serialize(uint8_t byte)
{
    if (packet_assert_length(off + 1, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    buf[off] = byte;
    off ++;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::serialize(uint16_t bytes)
{
    if (packet_assert_length(off + 2, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    buf[off] = (bytes & 0x00FF);
    buf[off + 1] = (bytes & 0xFF00) >> 8;

    off += 2;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::serialize(uint32_t bytes)
{
    if (packet_assert_length(off + 4, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    buf[off] = (bytes & 0x000000FF);
    buf[off + 1] = (bytes & 0x0000FF00) >> 8;
    buf[off + 2] = (bytes & 0x00FF0000) >> 16;
    buf[off + 3] = (bytes & 0xFF000000) >> 24;

    off += 4;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::serialize(uint64_t bytes)
{
    if (packet_assert_length(off + 8, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    buf[off] = (bytes & 0x00000000000000FF);
    buf[off + 1] = (bytes & 0x000000000000FF00) >> 8;
    buf[off + 2] = (bytes & 0x0000000000FF0000) >> 16;
    buf[off + 3] = (bytes & 0x00000000FF000000) >> 24;
    buf[off + 4] = (bytes & 0x000000FF00000000) >> 32;
    buf[off + 5] = (bytes & 0x0000FF0000000000) >> 40;
    buf[off + 6] = (bytes & 0x00FF000000000000) >> 48;
    buf[off + 7] = (bytes & 0xFF00000000000000) >> 56;

    off += 8;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::serialize(uint8_t *mac)
{
    if (packet_assert_length(off + FW_MACADDR_LEN, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    memcpy(&buf[off], mac, FW_MACADDR_LEN);

    off += FW_MACADDR_LEN;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::serialize(uint8_t *bufin, uint32_t buflen_to_copy)
{
    if (packet_assert_length(off + buflen_to_copy, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    memcpy(&buf[off], bufin, buflen_to_copy);

    off += buflen_to_copy;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint8_t &byte)
{
    if (packet_assert_length(off + 1, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    byte = buf[off];
    off ++;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint16_t &bytes)
{
    if (packet_assert_length(off + 2, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    bytes = (buf[off + 1]) | (buf[off] << 8);
    off += 2;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint32_t &bytes)
{
    if (packet_assert_length(off + 4, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    bytes = ((buf[off + 3] << 24) |
             (buf[off + 2] << 16) |
             (buf[off + 1] << 8) |
             buf[off]);
    off += 4;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint64_t &bytes)
{
    if (packet_assert_length(off + 8, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    bytes = (((uint64_t)(buf[off + 7]) << 56) |
             ((uint64_t)(buf[off + 6]) << 48) |
             ((uint64_t)(buf[off + 5]) << 40) |
             ((uint64_t)(buf[off + 4]) << 32) |
             (buf[off + 3] << 24) |
             (buf[off + 2] << 16) |
             (buf[off + 1] << 8) |
             buf[off]);
    off += 8;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint8_t *mac)
{
    if (packet_assert_length(off + FW_MACADDR_LEN, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    memcpy(mac, &buf[off], FW_MACADDR_LEN);
    off += FW_MACADDR_LEN;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint8_t *bufout, uint32_t buflen_to_copy)
{
    if (packet_assert_length(off + buflen_to_copy, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    memcpy(bufout, &buf[off], buflen_to_copy);
    off += buflen_to_copy;

    return fw_error_type::eNo_Error;
}

}

