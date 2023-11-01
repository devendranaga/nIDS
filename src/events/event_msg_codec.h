#ifndef __FW_EVENT_EVENT_MSG_CODEC_H__
#define __FW_EVENT_EVENT_MSG_CODEC_H__

#include <event.h>
#include <event_msg.h>

namespace firewall {

class event_msg_codec {
    public:
        explicit event_msg_codec() { }
        ~event_msg_codec() { }

        int serialize(event &e, event_msg *evt_msg);
        int deserialize(event &e, event_msg *evt_msg);
        int hash_and_encrypt(uint8_t *evt_buf, uint32_t evt_buf_len,
                             uint8_t *out_buf);
        int hash_and_decrypt(uint8_t *evt_buf, uint32_t evt_buf_len,
                             uint8_t *out_buf, const std::string &keyfile);
};

}

#endif

