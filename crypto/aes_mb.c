#include <string.h>
#include <stdlib.h>

#include "pub/err.h"
#include "aes.h"

#if defined(MBEDTLS_VERSION_2)
    // mbedTLS 2.x.x (e.g., 2.16.12)
    #include <mbedtls/aes.h>
#else
    // mbedTLS 3.x.x and newer
    #include <mbedtls/cipher.h>
#endif

// Helper function for encryption/decryption with mbedTLS
static byte_t *_crypto_aes(const byte_t *key, const byte_t *iv,
                           const byte_t *data, size_t data_size,
                           size_t *out_size_p, int enc, int key_bits)
{
    byte_t *ret = malloc(data_size); // Allocate output buffer
    if (!ret) return NULL;

#if defined(MBEDTLS_VERSION_2)
    // mbedTLS 2.x
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);

    int ret_code = (enc)
                       ? mbedtls_aes_setkey_enc(&aes_ctx, key, key_bits)
                       : mbedtls_aes_setkey_dec(&aes_ctx, key, key_bits);
    if (ret_code != 0) {
        mbedtls_aes_free(&aes_ctx);
        free(ret);
        return NULL;
    }

    size_t iv_off = 0;
    ret_code = mbedtls_aes_crypt_cfb128(
        &aes_ctx,
        enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        data_size,
        &iv_off,
        (unsigned char *)iv, // Cast to remove const qualifier
        data,
        ret
    );

    mbedtls_aes_free(&aes_ctx);

    if (ret_code != 0) {
        free(ret);
        return NULL;
    }

#else
    // mbedTLS 3.x
    mbedtls_cipher_context_t cipher_ctx;
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(
        key_bits == 128 ? MBEDTLS_CIPHER_AES_128_CFB : MBEDTLS_CIPHER_AES_256_CFB);

    if (!cipher_info) {
        free(ret);
        return NULL;
    }

    mbedtls_cipher_init(&cipher_ctx);
    if (mbedtls_cipher_setup(&cipher_ctx, cipher_info) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        free(ret);
        return NULL;
    }

    if (mbedtls_cipher_setkey(&cipher_ctx, key, key_bits, enc) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        free(ret);
        return NULL;
    }

    if (mbedtls_cipher_set_iv(&cipher_ctx, iv, 16) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        free(ret);
        return NULL;
    }

    if (mbedtls_cipher_reset(&cipher_ctx) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        free(ret);
        return NULL;
    }

    size_t out_size = 0;
    if (mbedtls_cipher_update(&cipher_ctx, data, data_size, ret, &out_size) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        free(ret);
        return NULL;
    }

    mbedtls_cipher_free(&cipher_ctx);
#endif

    if (out_size_p) *out_size_p = data_size; // Output size matches input size
    return ret;
}

// Define AES encryption and decryption functions
#define GEN_AES(mode, block_size) \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _enc( \
        const byte_t *key, const byte_t *iv, \
        const byte_t *data, size_t data_size, \
        size_t *out_size_p) \
    { \
        return _crypto_aes(key, iv, data, data_size, out_size_p, 1, block_size); \
    } \
    \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _dec( \
        const byte_t *key, const byte_t *iv, \
        const byte_t *ctext, size_t ctext_size, \
        size_t *out_size_p) \
    { \
        return _crypto_aes(key, iv, ctext, ctext_size, out_size_p, 0, block_size); \
    }

GEN_AES(cfb, 128)
GEN_AES(cfb, 256)

#undef GEN_AES
