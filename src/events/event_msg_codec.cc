#include <config.h>
#include <ether_types.h>
#include <protocols_types.h>
#include <event_msg_codec.h>
#include <crypto.h>

namespace firewall {

int event_msg_codec::serialize(event &e, event_msg *evt_msg)
{
    int total_len = 0;

    evt_msg->evt_type = e.evt_type;
    evt_msg->evt_desc = e.evt_details;
    evt_msg->rule_id = e.rule_id;
    evt_msg->ethertype = e.ethertype;

    total_len = sizeof(event_msg);

    switch (static_cast<Ether_Type>(e.ethertype)) {
        case Ether_Type::Ether_Type_IPv4: {
            event_ipv4_info *ipv4 = (event_ipv4_info *)evt_msg->data;

            ipv4->src_addr = e.src_addr;
            ipv4->dst_addr = e.dst_addr;
            ipv4->ttl = e.ttl;
            ipv4->protocol = e.protocol;

            total_len += sizeof(event_ipv4_info);

            switch (static_cast<protocols_types>(e.protocol)) {
                case protocols_types::Protocol_Tcp: {
                    event_tcp_info *tcp = (event_tcp_info *)ipv4->data;

                    tcp->src_port = e.src_port;
                    tcp->dst_port = e.dst_port;
                } break;
                default:
                break;
            }
        } break;
        default:
        break;
    }

    return total_len;
}

int event_msg_codec::deserialize(event &e, event_msg *evt_msg)
{
    e.evt_type = evt_msg->evt_type;
    e.evt_details = evt_msg->evt_desc;
    e.rule_id = evt_msg->rule_id;
    e.ethertype = evt_msg->ethertype;

    switch (static_cast<Ether_Type>(evt_msg->ethertype)) {
        case Ether_Type::Ether_Type_IPv4: {
            event_ipv4_info *ipv4 = (event_ipv4_info *)evt_msg->data;

            e.src_addr = ipv4->src_addr;
            e.dst_addr = ipv4->dst_addr;
            e.ttl = ipv4->ttl;
            e.protocol = ipv4->protocol;
        } break;
        default:
        break;
    }

    return 0;
}

int event_msg_codec::hash_and_encrypt(uint8_t *evt_buf, uint32_t evt_buf_len,
                                      uint8_t *enc_buf)
{
    firewall_config *conf = firewall_config::instance();
    event_msg_hdr *hdr;
    uint8_t *evt_data_ptr;
    int total_len = sizeof(event_msg_hdr) + evt_buf_len;
    crypto_hash hash;
    crypto_aes_ctr aes_ctr;
    int ret;

    hdr = (event_msg_hdr *)enc_buf;
    evt_data_ptr = enc_buf + sizeof(event_msg_hdr);

    hdr->version = EVT_FILE_VERSION;
    switch (conf->evt_config.hash_alg) {
        case event_hash_algorithm::SHA256: {
            uint32_t hash_len = 0;

            hdr->hash_alg = Hash_Algorithm::SHA2;
            hdr->hash_len = 32;
            ret = hash.sha2_256(hdr->hash, &hash_len, evt_buf, evt_buf_len);
            if (ret < 0) {
                return -1;
            }
            hdr->hash_len = hash_len;
        } break;
        default: // unsecured
            hdr->hash_alg = Hash_Algorithm::None;
        break;
    }
    switch (conf->evt_config.enc_alg) {
        case event_encryption_algorithm::AES_CTR_128: {
            uint32_t enc_len = 0;

            hdr->enc_alg = Encryption_Algorithm::AES_CTR_128;
            ret = aes_ctr.load_key(conf->evt_config.encryption_key);
            if (ret == -1) {
                return -1;
            }
            ret = aes_ctr.ctr_128_encrypt(evt_buf, evt_buf_len,
                                          evt_data_ptr, &enc_len, hdr->iv);
            if (ret < 0) {
                return -1;
            }
            hdr->enc_msg_len = enc_len;
            total_len = sizeof(event_msg_hdr) + hdr->enc_msg_len;
        } break;
        default: // unsecured
            hdr->enc_alg = Encryption_Algorithm::None;
        break;
    }

    return total_len;
}

int event_msg_codec::hash_and_decrypt(uint8_t *evt_buf, uint32_t evt_buf_len,
                                      uint8_t *out_buf, const std::string &keyfile)
{
    event_msg_hdr *evt_hdr = (event_msg_hdr *)evt_buf;
    uint8_t *enc_data_ptr = evt_buf + sizeof(event_msg_hdr);
    uint32_t out_buf_len = 0;
    int ret;

    switch (evt_hdr->enc_alg) {
        case Encryption_Algorithm::AES_CTR_128: {
            crypto_aes_ctr aes_ctr;

            ret = aes_ctr.load_key(keyfile);
            if (ret == -1) {
                return -1;
            }
            ret = aes_ctr.ctr_128_decrypt(enc_data_ptr,
                                          evt_hdr->enc_msg_len,
                                          out_buf,
                                          &out_buf_len,
                                          evt_hdr->iv);
            if (ret < 0) {
                return -1;
            }
        } break;
        default: // unsecured frame
            out_buf_len = evt_hdr->enc_msg_len;
            ret = 0;
        break;
    }

    switch (evt_hdr->hash_alg) {
        case Hash_Algorithm::SHA2: {
            crypto_hash hash;
            uint8_t hash_buf[64];
            uint32_t hash_len = 0;

            ret = hash.sha2_256(hash_buf, &hash_len, out_buf, out_buf_len);
            if (ret == -1) {
                return -1;
            }

            if (evt_hdr->hash_len != hash_len) {
                return -1;
            }
            ret = std::memcmp(hash_buf, evt_hdr->hash, hash_len);
            if (ret != 0) {
                return -1;
            }
        } break;
        default: // unsecured frame
            out_buf_len = evt_hdr->enc_msg_len;
            ret = 0;
        break;
    }

    return ret == 0 ? out_buf_len: -1;
}

}

