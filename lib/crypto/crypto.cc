/**
 * @brief - implements crypto wrappers.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <crypto.h>

namespace firewall {

/**
 * @brief - load key into key buffer.
 *
 * @param [in] keyfile - input keyfile
 * @param [inout] key - output key buffer.
 *
 * @return keysize on success -1 on failure.
 */
static int load_keyfile(const std::string &keyfile,
                        uint8_t *key)
{
    struct stat s;
    FILE *fp;
    int ret;

    fp = fopen(keyfile.c_str(), "r");
    if (!fp)
        return -1;

    ret = stat(keyfile.c_str(), &s);
    if (ret != 0) {
        fclose(fp);
        return -1;
    }

    //
    // read the key length bytes and return it
    if (fread(key, s.st_size, 1, fp) == 0)
        ret = -1;
    else
        ret = s.st_size;

    fclose(fp);
    return ret;
}

int crypto_hash::sha2_256(uint8_t *hash_in, uint32_t *hash_in_len,
                          const uint8_t *in, uint32_t in_len)
{
    EVP_MD_CTX *md_ctx;
    const EVP_MD *digest = EVP_sha256();
    int ret;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        return -1;

    ret = EVP_DigestInit_ex(md_ctx, digest, nullptr);
    if (ret != 1)
        goto deinit;

    ret = EVP_DigestUpdate(md_ctx, in, in_len);
    if (ret != 1)
        goto deinit;

    ret = EVP_DigestFinal_ex(md_ctx, hash_in, hash_in_len);
    if (ret != 1)
        goto deinit;

    EVP_MD_CTX_free(md_ctx);
    return 0;

deinit:
    EVP_MD_CTX_free(md_ctx);
    return -1;
}

int crypto_aes_ctr::load_key(const std::string &keyfile)
{
    return load_keyfile(keyfile, key_);
}

int crypto_aes_ctr::ctr_128_encrypt(uint8_t *data_in, uint32_t data_in_len,
                                    uint8_t *data_out, uint32_t *data_out_len,
                                    uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_ctr();
    int out_len = 0;
    int ret;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    RAND_bytes(iv, 16);

    ret = EVP_EncryptInit_ex(ctx, cipher, nullptr, key_, iv);
    if (ret != 1)
        goto deinit;

    ret = EVP_EncryptUpdate(ctx, data_out, &out_len, data_in, data_in_len);
    if (ret != 1)
        goto deinit;

    *data_out_len = out_len;

    ret = EVP_EncryptFinal(ctx, data_out + out_len, &out_len);
    if (ret != 1)
        goto deinit;

    *data_out_len += out_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

deinit:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int crypto_aes_ctr::ctr_128_decrypt(uint8_t *data_in, uint32_t data_in_len,
                                    uint8_t *data_out, uint32_t *data_out_len,
                                    uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_ctr();
    int out_len = 0;
    int ret;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    ret = EVP_DecryptInit_ex(ctx, cipher, nullptr, key_, iv);
    if (ret != 1)
        goto deinit;

    ret = EVP_DecryptUpdate(ctx, data_out, &out_len, data_in, data_in_len);
    if (ret != 1)
        goto deinit;

    *data_out_len = out_len;

    ret = EVP_DecryptFinal_ex(ctx, data_out + out_len, &out_len);
    if (ret != 1)
        goto deinit;

    *data_out_len += out_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

deinit:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

crypto_aes_ctr::crypto_aes_ctr()
{
    std::memset(key_, 0, sizeof(key_));
    keysize_ = 0;
}

crypto_aes_ctr::~crypto_aes_ctr() { }

}

