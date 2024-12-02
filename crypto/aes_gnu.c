#include <gnutls/crypto.h>
#include <stdlib.h>
#include "pub/err.h"
#include "aes.h"

static inline int validate_inputs(const byte_t *key, const byte_t *iv, const byte_t *data) {
    return key && iv && data;
}

byte_t *_crypto_gnutls(const gnutls_cipher_algorithm_t cipher,
                       const byte_t *key, const byte_t *iv,
                       const byte_t *data, size_t data_size,
                       size_t *out_size_p, int enc) {
    if (!validate_inputs(key, iv, data)) return NULL;

    gnutls_cipher_hd_t cipher_hd;
    gnutls_datum_t gkey = { (void *)key, 16 };  // Adjust key size as needed
    gnutls_datum_t giv = { (void *)iv, 16 };    // Adjust IV size as needed

    int ret = gnutls_cipher_init(&cipher_hd, cipher, &gkey, &giv);
    if (ret < 0) {
        fprintf(stderr, "Error initializing cipher: %s\n", gnutls_strerror(ret));
        return NULL;
    }

    byte_t *out = malloc(data_size);
    if (!out) {
        gnutls_cipher_deinit(cipher_hd);
        return NULL;
    }

    if (enc) {
        ret = gnutls_cipher_encrypt2(cipher_hd, data, data_size, out, data_size);
    } else {
        ret = gnutls_cipher_decrypt2(cipher_hd, data, data_size, out, data_size);
    }

    gnutls_cipher_deinit(cipher_hd);

    if (ret < 0) {
        fprintf(stderr, "Error during encryption/decryption: %s\n", gnutls_strerror(ret));
        free(out);
        return NULL;
    }

    *out_size_p = data_size;
    return out;
}

#if GNUTLS_VERSION_NUMBER >= 0x030800
// Code for GnuTLS 3.8.0 and newer
#define GEN_AES(mode, block_size) \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _enc(const byte_t *key, const byte_t *iv, \
                                                           const byte_t *data, size_t data_size, \
                                                           size_t *out_size_p) { \
        return _crypto_gnutls(GNUTLS_CIPHER_AES_ ## block_size ## _CFB, key, iv, data, data_size, out_size_p, 1); \
    } \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _dec(const byte_t *key, const byte_t *iv, \
                                                           const byte_t *ctext, size_t ctext_size, \
                                                           size_t *out_size_p) { \
        return _crypto_gnutls(GNUTLS_CIPHER_AES_ ## block_size ## _CFB, key, iv, ctext, ctext_size, out_size_p, 0); \
    }
#else
// Code for GnuTLS 3.6.x
#define GEN_AES(mode, block_size) \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _enc(const byte_t *key, const byte_t *iv, \
                                                           const byte_t *data, size_t data_size, \
                                                           size_t *out_size_p) { \
        return _crypto_gnutls(GNUTLS_CIPHER_AES_ ## block_size ## _CFB8, key, iv, data, data_size, out_size_p, 1); \
    } \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _dec(const byte_t *key, const byte_t *iv, \
                                                           const byte_t *ctext, size_t ctext_size, \
                                                           size_t *out_size_p) { \
        return _crypto_gnutls(GNUTLS_CIPHER_AES_ ## block_size ## _CFB8, key, iv, ctext, ctext_size, out_size_p, 0); \
    }
#endif

GEN_AES(cfb, 128)
GEN_AES(cfb, 256)

#undef GEN_AES