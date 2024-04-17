/*
 * wolfhsm/wh_common.h
 *
 */

#ifndef WOLFHSM_WH_COMMON_H_
#define WOLFHSM_WH_COMMON_H_

/* TODO: consider using the version without _t */
#include <stdint.h>

/* Compiler-specific structure packing */
#if (defined(__IAR_SYSTEMS_ICC__) && (__IAR_SYSTEMS_ICC__ > 8)) || \
    defined(__GNUC__)
#define WOLFHSM_PACK __attribute__((packed))
#else
    #define WOLFHSM_PACK
#endif

/* Compiler-specific alignment */
#if defined(__IAR_SYSTEMS_ICC__) || defined(__GNUC__)
#define WOLFHSM_ALIGN(_x) __attribute__((aligned((_x))))
#else
    #define WOLFHSM_ALIGN(_x)
#endif

/* Default alignment for any structs shared between server and client */
#define WOLFHSM_DEFAULT_ALIGNMENT sizeof(uint64_t)

/* C11-dependent use of static assert */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
    /* Use the built-in _Static_assert if available */
    #define WH_STATIC_ASSERT(_expr, _msg) _Static_assert(_expr, _msg)
#else
    /* Define a do-nothing macro for compilers that don't support _Static_assert */
    #define WH_STATIC_ASSERT(_expr, _msg) /* Nothing */
#endif


/* Device Id to be registered and passed to wolfCrypt functions */
#define WOLFHSM_DEV_ID 0x5748534D  /* "WHSM" */

#define WOLFHSM_DIGEST_STUB 8

/** Resource allocations */
enum {
    WOLFHSM_NUM_COUNTERS = 8,       /* Number of non-volatile 32-bit counters */
    WOLFHSM_NUM_RAMKEYS = 2,        /* Number of RAM keys */
    WOLFHSM_NUM_NVMOBJECTS = 32,    /* Number of NVM objects in the directory */
    WOLFHSM_NUM_MANIFESTS = 8,      /* Number of compiletime manifests */
    WOLFHSM_KEYCACHE_BUFSIZE = 512, /* Size in bytes of key cache buffer  */
};


/** Non-volatile counters */

/* HSM Counter identifier type. */
typedef uint16_t whCounterId;


/** Key Management */

/* HSM key identifier type.  Top nibble identifies key type/location */
typedef uint16_t whKeyId;

#define WOLFHSM_KEYID_MASK 0xF000
#define WOLFHSM_KEYID_CRYPTO 0x1000
#define WOLFHSM_KEYID_SHE 0x2000
#define WOLFHSM_KEYID_SHE_RAM 0x3000
#define MAKE_WOLFHSM_KEYID(_kind, _id) \
    (whKeyId)(((_kind) & WOLFHSM_KEYID_MASK) | ((_id) & ~WOLFHSM_KEYID_MASK))


/** NVM Management */

/* HSM NVM object identifier type. */
typedef uint16_t whNvmId;

/* HSM NVM Size type */
typedef uint16_t whNvmSize;

/* HSM NVM Access type */
typedef uint16_t whNvmAccess;

/* HSM NVM Flags type */
typedef uint16_t whNvmFlags;

/* HSM NVM metadata structure */
enum {
    WOLFHSM_NVM_LABEL_LEN = 24,
    WOLFHSM_NVM_METADATA_LEN = 32,
    WOLFHSM_NVM_MAX_OBJECT_SIZE = 65535,
};

/* List flags */
#define WOLFHSM_NVM_ACCESS_ANY (0xFFFF)
#define WOLFHSM_NVM_FLAGS_ANY (0xFFFF)

/* User-specified metadata for an NVM object */
typedef struct {
    whNvmId id;             /* Unique identifier */
    whNvmAccess access;     /* Growth */
    whNvmFlags flags;       /* Growth */
    whNvmSize len;          /* Length of data in bytes */
    uint8_t label[WOLFHSM_NVM_LABEL_LEN];
} whNvmMetadata;
WH_STATIC_ASSERT(
    sizeof(whNvmMetadata) == WOLFHSM_NVM_METADATA_LEN,
    "Size of whNvmMetadata doesn't match WOLFHSM_NVM_METADATA_LEN");


/** Manifest storage  */

enum {
    WOLFHSM_MANIFEST_CMAC_LEN = 16,
};

typedef struct {
    void* address;              /* Flash address that matches this entry */
    /* TODO: Make this match customer format */
    uint8_t payload_cmac[WOLFHSM_MANIFEST_CMAC_LEN];  /* CMAC of the image */
    uint8_t* payload_start;     /* Flash address where the payload starts */
    uint32_t payload_len;       /* Leng of the payload */
    uint8_t manifest_cmac[WOLFHSM_MANIFEST_CMAC_LEN]; /* CMAC of the manifest */
} whManifest_ex;

/* TODO Update Stored manifest data at compile time */

extern const whManifest_ex manifests[WOLFHSM_NUM_MANIFESTS];

/* Custom request shared defs */
#define WH_CUSTOM_CB_NUM_CALLBACKS 8
#define WOLFHSM_ID_ERASED 0

#endif /* WOLFHSM_WH_COMMON_H_ */
