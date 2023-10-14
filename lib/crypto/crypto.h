/**
 * @brief - Implements crypto interface for firewall.
 * 
 * The use is in the encryption of the event data before writing to a file.
 * @copyright - 2023-present. All rights reserved.
*/
#ifndef __FW_LIB_CRYPTO_H__
#define __FW_LIB_CRYPTO_H__

#include <stdint.h>

namespace firewall {

class crypto_hash {
    public:
        explicit crypto_hash() { }
        ~crypto_hash() { }

        int sha2_256(uint8_t *hash_in, uint32_t *hash_len,
                     const uint8_t *input, uint32_t input_len);
};

class crypto_aes_gcm {
    public:
        explicit crypto_aes_gcm();
        ~crypto_aes_gcm() { }

        int gcm_128(uint8_t *data_in, uint32_t data_len,
                    uint8_t *data_out, uint32_t *data_out_len,
                    uint8_t *tag, uint8_t *iv);
};

}

#endif
