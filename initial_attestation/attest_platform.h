
#ifndef __ATTEST_PLATFORM_H
#define __ATTEST_PLATFORM_H

#include "attest_types.h"

#define IAT_NONCE                          10  /* EAT nonce */
#define IAT_INSTANCE_ID                    256 /* EAT ueid */
#define IAT_PROFILE_DEFINITION             265 /* EAT eat_profile */
#define IAT_BOOT_SEED                      268 /* EAT bootseed */
#define IAT_ARM_RANGE_BASE                 (2393)
#define IAT_CLIENT_ID                      (IAT_ARM_RANGE_BASE + 1)
#define IAT_SECURITY_LIFECYCLE             (IAT_ARM_RANGE_BASE + 2)
#define IAT_IMPLEMENTATION_ID              (IAT_ARM_RANGE_BASE + 3)
/* Reserved                                (IAT_ARM_RANGE_BASE + 4) */
#define IAT_CERTIFICATION_REFERENCE        (IAT_ARM_RANGE_BASE + 5)
#define IAT_SW_COMPONENTS                  (IAT_ARM_RANGE_BASE + 6)
#define IAT_VERIFICATION_SERVICE           (IAT_ARM_RANGE_BASE + 7)

#define BOOT_SEED_SIZE                      (32u)

#define IMPLEMENTATION_ID_MAX_SIZE          (32u)

#define PROFILE_DEFINITION_MAX_SIZE         (48u)
                              
enum attest_plat_security_lifecycle_t {
    ATTEST_PLAT_SLC_UNKNOWN                   = 0x0000u,
    ATTEST_PLAT_SLC_ASSEMBLY_AND_TEST         = 0x1000u,
    ATTEST_PLAT_SLC_PSA_ROT_PROVISIONING      = 0x2000u,
    ATTEST_PLAT_SLC_SECURED                   = 0x3000u,
    ATTEST_PLAT_SLC_NON_PSA_ROT_DEBUG         = 0x4000u,
    ATTEST_PLAT_SLC_RECOVERABLE_PSA_ROT_DEBUG = 0x5000u,
    ATTEST_PLAT_SLC_DECOMMISSIONED            = 0x6000u,
    ATTEST_PLAT_SLC_MAX_VALUE                 = UINT32_MAX,
};

/* Initial attestation: SW components / SW modules
 * This list is intended to be adjusted per device. It contains more SW
 * components than currently available in TF-M project. It serves as an example,
 * what kind of SW components might be available.
 */
#define ATTEST_PLAT_SW_GENERAL     0x00
#define ATTEST_PLAT_SW_BL2         0x01
#define ATTEST_PLAT_SW_PROT        0x02
#define ATTEST_PLAT_SW_AROT        0x03
#define ATTEST_PLAT_SW_SPE         0x04
#define ATTEST_PLAT_SW_NSPE        0x05
#define ATTEST_PLAT_SW_S_NS        0x06
#define ATTEST_PLAT_SW_MAX         0x07


enum attest_plat_err_t {
    ATTEST_PLAT_ERR_SUCCESS = 0,
    ATTEST_PLAT_ERR_SYSTEM_ERR = 0x3A5C,
    ATTEST_PLAT_ERR_MAX_VALUE = 0x55A3,
    ATTEST_PLAT_ERR_INVALID_INPUT = 0xA3C5,
    ATTEST_PLAT_ERR_UNSUPPORTED = 0xC35A,
    ATTEST_PLAT_ERR_NOT_PERMITTED = 0xC5A3,
    /* Following entry is only to ensure the error code of int size */
    ATTEST_PLAT_ERR_FORCE_INT_SIZE = INT_MAX
};

/**
 * \brief The persistent key identifiers for TF-M builtin keys.
 *
 * \note The value of TFM_BUILTIN_KEY_ID_MIN (and therefore of the whole range) is
 *       completely arbitrary except for being inside the PSA builtin keys range.
 *       The range is specified by the limits defined through MBEDTLS_PSA_KEY_ID_BUILTIN_MIN
 *       and MBEDTLS_PSA_KEY_ID_BUILTIN_MAX
 */
enum attest_plat_builtin_key_id_t {
    ATTEST_PLAT_BUILTIN_KEY_ID_MIN = 0x7FFF815Bu,
    ATTEST_PLAT_BUILTIN_KEY_ID_HUK,
    ATTEST_PLAT_BUILTIN_KEY_ID_IAK,
    ATTEST_PLAT_BUILTIN_KEY_ID_PLAT_SPECIFIC_MIN = 0x7FFF816Bu,
    ATTEST_PLAT_BUILTIN_KEY_ID_MAX = 0x7FFF817Bu,
};

/**
 * \brief Get the Implementation ID of the device.
 *
 * This mandatory claim represents the original implementation signer of the
 * attestation key and identifies the contract between the report and
 * verification. A verification service will use this claim to locate the
 * details of the verification process. The claim will be represented by a
 * custom EAT claim with a value consisting of a CBOR byte string. The size of
 * this string will normally be 32 bytes to accommodate a 256 bit hash.
 *
 * \param[in/out] size  As an input value it indicates the size of the caller
 *                      allocated buffer (in bytes) to store the implementation
 *                      ID. At return its value is updated with the exact size
 *                      of the implementation ID.
 * \param[out]    buf   Pointer to the buffer to store the implementation ID
 *
 * \return  Returns error code specified in \ref tfm_plat_err_t
 */
extern enum attest_plat_err_t attest_plat_get_implementation_id(uint32_t *size, uint8_t  *buf);

/**
 * \brief Gets the boot seed, which is a constant random number during a boot
 *        cycle.
 *
 * \param[in]  size The required size of boot seed in bytes
 * \param[out] buf  Pointer to the buffer to store boot seed
 *
 * \return  TFM_PLAT_ERR_SUCCESS if the value is generated correctly. Otherwise,
 *          it returns TFM_PLAT_ERR_SYSTEM_ERR.
 */
extern enum attest_plat_err_t attest_plat_get_boot_seed(uint32_t size, uint8_t *buf);

/**
 * \brief Retrieve the security lifecycle of the device
 *
 * Security lifecycle is a mandatory claim in the initial attestation token.
 *
 * \return According to \ref tfm_security_lifecycle_t
 */
extern enum attest_plat_security_lifecycle_t attest_hal_get_security_lifecycle(void);

/**
 * \brief Retrieve the name of the profile definition document for initial
 *        attestation.
 *
 *  This document describes the 'profile' of the initial attestation token,
 *  being a full description of the claims, their usage, verification and
 *  token signing.
 *
 * \param[in/out] size  As an input value it indicates the size of the caller
 *                      allocated buffer (in bytes) to store the profile
 *                      definition. At return its value is updated with the
 *                      exact size of the profile definition.
 * \param[out]    buf   Pointer to the buffer to store the profile definition.
 *
 * \return  Returns error code specified in \ref tfm_plat_err_t
 */
extern enum attest_plat_err_t attest_hal_get_profile_definition(uint32_t *size, uint8_t *buf);

#endif // __ATTEST_PLATFORM_H