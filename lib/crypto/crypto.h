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

/**
 * @brief - Implements hash functions.
 */
class crypto_hash {
    public:
        explicit crypto_hash() { }
        ~crypto_hash() { }

        /**
         * @brief - do sha256 on the given input.
         *
         * @param [out] hash_in - output hash
         * @param [out] hash_len - ouput hash length
         * @param [in] input - input message
         * @param [in] input_len - input message length
         *
         * @return 0 on succcess -1 on failure.
         */
        int sha2_256(uint8_t *hash_in, uint32_t *hash_len,
                     const uint8_t *input, uint32_t input_len);
};

/**
 * @brief - Implements AES-CTR functions.
 */
class crypto_aes_ctr {
    public:
        explicit crypto_aes_ctr();
        ~crypto_aes_ctr();

        /**
         * @brief - load key into RAM.
         *
         * @param [in] keyfile - input key file.
         *
         * @return length of the key on success -1 on failure.
         */
        int load_key(const std::string &keyfile);

        /**
         * @brief - perform AES-128-CTR encryption.
         *
         * @param [in] data_in - input data
         * @param [in] data_in_len - input data length
         * @param [out] data_out - output encrypted data
         * @param [out] data_out_len - output encrypted data length
         * @param [out] iv - output iv
         *
         * @return 0 on success -1 on failure.
         */
        int ctr_128_encrypt(uint8_t *data_in, uint32_t data_in_len,
                            uint8_t *data_out, uint32_t *data_out_len,
                            uint8_t *iv);

        /**
         * @brief - perform AES-128-CTR decryption.
         *
         * @param [in] data_in - input encrypted data
         * @param [in] data_in_len - input encrypted data length
         * @param [out] data_out - output decrypted data
         * @param [out] data_out_len - output decrypted data length
         * @param [in] iv - input iv
         *
         * @return 0 on success -1 on failure.
         */
        int ctr_128_decrypt(uint8_t *data_in, uint32_t data_in_len,
                            uint8_t *data_out, uint32_t *data_out_len,
                            uint8_t *iv);

    private:
        uint8_t key_[64];
        uint32_t keysize_;
};

}

#endif

