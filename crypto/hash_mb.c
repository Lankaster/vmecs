#include <mbedtls/md5.h>
#include <mbedtls/md.h>
#include "hash.h"

// MD5 hash function for mbedTLS (compatible with both 2.x and 3.x)
int crypto_md5(const byte_t *data, size_t size, data128_t hash)
{
    mbedtls_md5_context ctx;

    mbedtls_md5_init(&ctx);
    if (mbedtls_md5_starts_ret(&ctx) != 0 ||
        mbedtls_md5_update_ret(&ctx, data, size) != 0 ||
        mbedtls_md5_finish_ret(&ctx, hash) != 0) {
        mbedtls_md5_free(&ctx);
        return -1; // Indicate failure
    }

    mbedtls_md5_free(&ctx);
    return 0;
}

// HMAC-MD5 function for mbedTLS (compatible with both 2.x and 3.x)
int crypto_hmac_md5(const byte_t *key, size_t key_size,
                    const byte_t *data, size_t data_size,
                    data128_t hash)
{
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);

    if (!md_info) return -1; // MD5 not supported

    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) { // 1 enables HMAC mode
        mbedtls_md_free(&ctx);
        return -1;
    }

    if (mbedtls_md_hmac_starts(&ctx, key, key_size) != 0 ||
        mbedtls_md_hmac_update(&ctx, data, data_size) != 0 ||
        mbedtls_md_hmac_finish(&ctx, hash) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    mbedtls_md_free(&ctx);
    return 0;
}

// FNV-1a hash function (common implementation)
uint32_t crypto_fnv1a(const byte_t *data, size_t data_size)
{
    uint32_t hash = 0x811c9dc5;
    const uint32_t p = 0x01000193;

    while (data_size--)
        hash = (hash ^ *data++) * p;

    return hash;
}
