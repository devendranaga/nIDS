#include <packet.h>

namespace firewall {

packet::packet()
{
    buf = nullptr;
    buf_len = 0;
    off = 0;
}

packet::packet(uint32_t pkt_len) : buf_len(pkt_len), off(0)
{
    buf = (uint8_t *)calloc(1, pkt_len);
    if (!buf) {
        throw std::runtime_error("cannot allocate packet memory");
    }
}

packet::~packet()
{
}

static inline bool packet_assert_length(int in_bytes, int given_len)
{
    return (in_bytes >= given_len);
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

    off += 3;

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

    bytes = (buf[off + 1] >> 8) | (buf[off]);
    off += 2;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::deserialize(uint32_t &bytes)
{
    if (packet_assert_length(off + 4, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    bytes = ((buf[off + 3] >> 24) |
             (buf[off + 2] >> 16) |
             (buf[off + 1] >> 8) |
             buf[off]);
    off += 4;

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

int packet::create(uint8_t *pkt, uint32_t pkt_len)
{
    buf_len = pkt_len;

    buf = (uint8_t *)calloc(1, pkt_len + 1);
    if (!buf) {
        return -1;
    }

    memcpy(buf, pkt, pkt_len);

    return 0;
}

void packet::free_pkt()
{
    if (buf) {
        free(buf);
        buf = nullptr;
    }
}

}

