/**
 * @brief - Implements crypto interface for firewall.
 * 
 * The use is in the encryption of the event data before writing to a file.
 * @copyright - 2023-present. All rights reserved.
*/
#ifndef __FW_LIB_CRYPTO_H__
#define __FW_LIB_CRYPTO_H__

#include <stdint.h>
#include <string>

namespace firewall {

class crypto_hash {
    public:
        explicit crypto_hash() { }
        ~crypto_hash() { }

        int sha2_256(uint8_t *hash_in, uint32_t *hash_len,
                     const uint8_t *input, uint32_t input_len);
};

class crypto_aes_ctr {
    public:
        explicit crypto_aes_ctr();
        ~crypto_aes_ctr();

        int load_key(const std::string &keyfile);
        int ctr_128_encrypt(uint8_t *data_in, uint32_t data_in_len,
                            uint8_t *data_out, uint32_t *data_out_len,
                            uint8_t *iv);

    private:
        uint8_t key_[64];
        uint32_t keysize_;
};

}

#endif
