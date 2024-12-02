#include <gnutls/crypto.h>
#include "hash.h"

// Compute MD5 hash using GnuTLS
int crypto_md5(const byte_t *data, size_t size, data128_t hash)
{
    int ret = gnutls_hash_fast(GNUTLS_DIG_MD5, data, size, hash);
    if (ret < 0) {
        fprintf(stderr, "Error calculating MD5 hash: %s\n", gnutls_strerror(ret));
        return -1;
    }
    return 0;
}

// Compute HMAC-MD5 using GnuTLS
int crypto_hmac_md5(const byte_t *key, size_t key_size,
                    const byte_t *data, size_t data_size,
                    data128_t hash)
{
    gnutls_hmac_hd_t hmac_ctx;
    int ret = gnutls_hmac_init(&hmac_ctx, GNUTLS_MAC_MD5, key, key_size);
    if (ret < 0) {
        fprintf(stderr, "Error initializing HMAC context: %s\n", gnutls_strerror(ret));
        return -1;
    }

    ret = gnutls_hmac(hmac_ctx, data, data_size);
    if (ret < 0) {
        fprintf(stderr, "Error updating HMAC: %s\n", gnutls_strerror(ret));
        gnutls_hmac_deinit(hmac_ctx, NULL);
        return -1;
    }

    gnutls_hmac_deinit(hmac_ctx, hash); // Finalize HMAC and store result
    return 0;
}

// Compute FNV-1a hash
uint32_t crypto_fnv1a(const byte_t *data, size_t data_size)
{
    uint32_t hash = 0x811c9dc5;
    const uint32_t prime = 0x01000193;

    while (data_size--) {
        hash ^= *data++;
        hash *= prime;
    }

    return hash;
}
