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
    if (buf) {
        free(buf);
    }
}

static inline bool packet_assert_length(int in_bytes, int given_len)
{
    return (in_bytes >= given_len);
}

fw_error_type packet::serialize(uint8_t byte)
{
    if (packet_assert_length(1, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    buf[off] = byte;
    off ++;

    return fw_error_type::eNo_Error;
}

fw_error_type packet::serialize(uint16_t bytes)
{
    if (packet_assert_length(2, buf_len)) {
        return fw_error_type::eOut_Of_Bounds;
    }

    buf[off] = (bytes & 0x00FF);
    buf[off + 1] = (bytes & 0xFF00) >> 8;

    off += 2;

    return fw_error_type::eNo_Error;
}

}

