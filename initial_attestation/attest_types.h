
#ifndef __ATTEST_TYPES_H
#define __ATTEST_TYPES_H

#if ATTEST_USE_BUILTIN_TYPES

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

/*
 * TODO: The implementation from TrustedFirmware-m uses PSA APU but this API
 * dependend to mbedtls headers as well, so not portable to other libraries even
 * to different versions of mbedTLS.
 *
 * As a hacky solution, we just collect type definitions from TrustedFirmware-m
 * (SHA:f1e11dd4f3481b38ce6b0e2a404613fbf4fbb328)
 *
 * Let us find a better way to handle this
 */
 
/* -------------------------------------------------------------------------- */
/* psa/crypto_types.h                                                         */
/* -------------------------------------------------------------------------- */
typedef int32_t     psa_status_t;
typedef uint32_t    psa_key_handle_t;
typedef uint32_t    psa_algorithm_t;

/* -------------------------------------------------------------------------- */
/* psa/crypto_values.h                                                        */
/* -------------------------------------------------------------------------- */
#define PSA_SUCCESS                             ((psa_status_t)0)
#define PSA_ERROR_GENERIC_ERROR                 ((psa_status_t)-132)
#define PSA_ERROR_INVALID_ARGUMENT              ((psa_status_t)-135)
#define PSA_ERROR_BUFFER_TOO_SMALL              ((psa_status_t)-138)
#define PSA_ERROR_SERVICE_FAILURE               ((psa_status_t)-144)

#define PSA_ALG_HASH_MASK                       ((psa_algorithm_t) 0x000000ff)

#define PSA_ALG_MD5                             ((psa_algorithm_t) 0x02000003)
#define PSA_ALG_RIPEMD160                       ((psa_algorithm_t) 0x02000004)
#define PSA_ALG_SHA_1                           ((psa_algorithm_t) 0x02000005)
#define PSA_ALG_SHA_224                         ((psa_algorithm_t) 0x02000008)
#define PSA_ALG_SHA_256                         ((psa_algorithm_t) 0x02000009)
#define PSA_ALG_SHA_384                         ((psa_algorithm_t) 0x0200000a)
#define PSA_ALG_SHA_512                         ((psa_algorithm_t) 0x0200000b)
#define PSA_ALG_SHA_512_224                     ((psa_algorithm_t) 0x0200000c)
#define PSA_ALG_SHA_512_256                     ((psa_algorithm_t) 0x0200000d)
#define PSA_ALG_SHA3_224                        ((psa_algorithm_t) 0x02000010)
#define PSA_ALG_SHA3_256                        ((psa_algorithm_t) 0x02000011)
#define PSA_ALG_SHA3_384                        ((psa_algorithm_t) 0x02000012)
#define PSA_ALG_SHA3_512                        ((psa_algorithm_t) 0x02000013)

#define PSA_ALG_CATEGORY_HASH                   ((psa_algorithm_t) 0x02000000)

#define PSA_ALG_HMAC_GET_HASH(hmac_alg)                             \
            (PSA_ALG_CATEGORY_HASH | ((hmac_alg) & PSA_ALG_HASH_MASK))

/* -------------------------------------------------------------------------- */
/* psa/crypto_sizes.h                                                         */
/* -------------------------------------------------------------------------- */

#define PSA_BITS_TO_BYTES(bits) (((bits) + 7u) / 8u)

#define PSA_HASH_LENGTH(alg)                                        \
    (                                                               \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD5 ? 16u :           \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 20u :     \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_1 ? 20u :         \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_224 ? 28u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_256 ? 32u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_384 ? 48u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512 ? 64u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 28u :   \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 32u :   \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 28u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 32u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 48u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 64u :      \
        0u)

extern psa_status_t psa_hash_compute(psa_algorithm_t alg, 
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length);
#else

#error "Not supported yet"

#endif

#endif /* __ATTEST_TYPES_H */