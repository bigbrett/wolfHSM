/*
 * Copyright (C) 2025 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wolfhsm/wh_settings.h"


#include <stdint.h>
#include <string.h> /* For memset, memcpy */

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_KEYWRAP

#include "wh_test_common.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_object.h"

/* Common defines */
#define WH_TEST_KEKID 10

/* AES GCM Specific defines */
#ifdef HAVE_AESGCM

#define WH_TEST_AESGCM_KEY_OFFSET 0x1000
#define WH_TEST_AESGCM_KEYID 20
#define WH_TEST_AES_KEYSIZE 32
#define WH_TEST_AES_TEXTSIZE 16
#define WH_TEST_AES_WRAPPED_KEYSIZE                         \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))

#endif /* HAVE_AESGCM */

static int _InitServerKek(whClientContext* client)
{
    /* IMPORTANT NOTE: Server KEK is typically intrinsic or set during
     * provisioning. Uploading the KEK via the client is for testing purposes
     * only and not intended as a recommendation */
    whKeyId    serverKeyId             = WH_TEST_KEKID;
    whNvmFlags flags = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_WRAP;
    uint8_t    label[WH_NVM_LABEL_LEN] = "Server KEK key";
    uint8_t    kek[] = {0x03, 0x03, 0x0d, 0xd9, 0xeb, 0x18, 0x17, 0x2e,
                        0x06, 0x6e, 0x19, 0xce, 0x98, 0x44, 0x54, 0x0d,
                        0x78, 0xa0, 0xbe, 0xe7, 0x35, 0x43, 0x40, 0xa4,
                        0x22, 0x8a, 0xd1, 0x0e, 0xa3, 0x63, 0x1c, 0x0b};

    return wh_Client_ObjectCacheAdd(client, WH_KEYTYPE_CRYPTO, &serverKeyId,
                                    WH_NVM_ACCESS_ANY, flags, kek,
                                    sizeof(kek), label, sizeof(label));
}

static int _CleanupServerKek(whClientContext* client)
{
    return wh_Client_ObjectCacheEvict(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID);
}

#ifdef HAVE_AESGCM

static int _AesGcm_TestKeyWrap(whClientContext* client, WC_RNG* rng)
{

    int           ret = 0;
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpPlainKeySz = sizeof(tmpPlainKey);
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    whKeyId       wrappedKeyId = WH_KEYID_ERASED;
    whNvmFlags    wrapFlags = WH_NVM_FLAGS_USAGE_ANY;
    uint8_t       wrapLabel[WH_NVM_LABEL_LEN] = "AES Key Label";
    whNvmAccess   tmpAccess = 0;
    whNvmFlags    tmpFlags  = 0;
    uint8_t       tmpLabel[WH_NVM_LABEL_LEN] = {0};

    Aes           aes[1];
    const uint8_t plaintext[] = "hello, wolfSSL AES-GCM!";
    uint8_t       ciphertext[sizeof(plaintext)];
    uint8_t       decrypted[sizeof(plaintext)];

    uint8_t       tag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t       iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    const uint8_t aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                           0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                           0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};


    ret = wc_RNG_GenerateBlock(rng, plainKey, sizeof(plainKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        return ret;
    }

    ret = wh_Client_ObjectWrap(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                               WC_CIPHER_AES_GCM, plainKey, sizeof(plainKey),
                               WH_NVM_ACCESS_ANY, wrapFlags, 0, wrapLabel,
                               WH_NVM_LABEL_LEN, wrappedKey, &wrappedKeySz);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyWrap %d\n", ret);
        return ret;
    }

    ret = wh_Client_ObjectUnwrapCache(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                      WC_CIPHER_AES_GCM, wrappedKey,
                                      wrappedKeySz, WH_KEYID_ERASED,
                                      &wrappedKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyWrapCache %d\n", ret);
        return ret;
    }

    /* Initialize AES context */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    ret =
        wh_Client_AesSetKeyId(aes, wrappedKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesSetKeyId %d\n", ret);
        return ret;
    }

    /* Generate a random IV */
    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for AES-GCM key %d\n",
                       ret);
        return ret;
    }

    /* Request the server to encrypt some data using the
     * unwrapped and cached key via the key ID */
    ret = wc_AesGcmEncrypt(aes, ciphertext, plaintext, sizeof(plaintext), iv,
                           sizeof(iv), tag, sizeof(tag), aad, sizeof(aad));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
        return ret;
    }

    /* Request the server to decrypt the encrypted data using the
     * unwrapped and cached key via the key ID */
    ret = wc_AesGcmDecrypt(aes, decrypted,                 /* out */
                           ciphertext, sizeof(ciphertext), /* in, inLen */
                           iv, sizeof(iv),                 /* iv, ivLen */
                           tag, sizeof(tag),  /* authTag, authTagSz */
                           aad, sizeof(aad)); /* authIn (AAD), authInSz */
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n", ret);
        return ret;
    }

    /* Check if the decrypted data matches an expected value */
    if (memcmp(decrypted, plaintext, sizeof(decrypted)) != 0) {
        WH_ERROR_PRINT("Decrypted value does not match expected value\n");
        return -1;
    }

    ret = wh_Client_ObjectUnwrapExport(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                       WC_CIPHER_AES_GCM, wrappedKey,
                                       wrappedKeySz, tmpPlainKey, &tmpPlainKeySz,
                                       &tmpAccess, &tmpFlags, tmpLabel,
                                       WH_NVM_LABEL_LEN);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyUnwrapAndExport %d\n", ret);
        return ret;
    }

    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap key failed to match\n");
        return -1;
    }

    if (tmpFlags != wrapFlags) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap flags failed to match\n");
        return -1;
    }

    if (memcmp(wrapLabel, tmpLabel, WH_NVM_LABEL_LEN) != 0) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap label failed to match\n");
        return -1;
    }

    /* Cache a local key using the same numeric ID to confirm coexistence */
    {
        whKeyId       localKeyId = WH_TEST_AESGCM_KEYID;
        uint8_t       localLabel[WH_NVM_LABEL_LEN] = "LocalKeySameId";
        const uint8_t localKey[WH_TEST_AES_KEYSIZE] = {0};

        ret = wh_Client_ObjectCacheAdd(client, WH_KEYTYPE_CRYPTO, &localKeyId,
                                       WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
                                       (uint8_t*)localKey, sizeof(localKey),
                                       localLabel,
                                       (uint16_t)sizeof("LocalKeySameId"));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache local key with shared ID %d\n", ret);
            return ret;
        }
        if (localKeyId != WH_TEST_AESGCM_KEYID) {
            WH_ERROR_PRINT("Local key ID mismatch (expected %u, got %u)\n",
                           WH_TEST_AESGCM_KEYID, localKeyId);
            return WH_ERROR_ABORTED;
        }
        WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvict(client, WH_KEYTYPE_CRYPTO, localKeyId));
    }

    wh_Client_ObjectCacheEvict(client, WH_KEYTYPE_CRYPTO, wrappedKeyId);
    wc_AesFree(aes);

    return ret;
}

static int _AesGcm_TestDataWrap(whClientContext* client)
{
    int      ret = 0;
    uint8_t  data[] = "Example data!";
    uint8_t  unwrappedData[sizeof(data)] = {0};
    uint16_t unwrappedDataSz = sizeof(unwrappedData);
    /* ObjectWrap adds metadata to the blob, so buffer needs to be bigger */
    uint8_t  wrappedData[sizeof(data) + sizeof(whNvmMetadata) +
                          WH_KEYWRAP_AES_GCM_HEADER_SIZE] = {0};
    uint16_t wrappedDataSz = sizeof(wrappedData);

    ret = wh_Client_ObjectWrap(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                WC_CIPHER_AES_GCM, data, sizeof(data),
                                WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, 0,
                                NULL, 0, wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to ObjectWrap data %d\n", ret);
        return ret;
    }

    ret = wh_Client_ObjectUnwrapExport(client, WH_KEYTYPE_CRYPTO,
                                        WH_TEST_KEKID, WC_CIPHER_AES_GCM,
                                        wrappedData, wrappedDataSz,
                                        unwrappedData, &unwrappedDataSz,
                                        NULL, NULL, NULL, 0);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to ObjectUnwrapExport data %d\n", ret);
        return ret;
    }

    if (memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("Unwrapped data failed to match input data\n");
        return -1;
    }

    return ret;
}

static int _AesGcm_TestKeyUnwrapUnderflow(whClientContext* client)
{
    int           ret;
    uint8_t       dummyBuf[1] = {0};
    uint8_t       tmpKey[WH_TEST_AES_KEYSIZE] = {0};
    uint16_t      tmpKeySz = sizeof(tmpKey);
    whKeyId       wrappedKeyId = WH_KEYID_ERASED;

    /* wrappedKeySz=0: must return WH_ERROR_BADARGS, not underflow */
    ret = wh_Client_ObjectUnwrapExport(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                       WC_CIPHER_AES_GCM, dummyBuf, 0,
                                       tmpKey, &tmpKeySz, NULL, NULL, NULL, 0);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndExport(sz=0) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* wrappedKeySz=1: must return WH_ERROR_BADARGS, not underflow */
    tmpKeySz = sizeof(tmpKey);
    ret = wh_Client_ObjectUnwrapExport(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                       WC_CIPHER_AES_GCM, dummyBuf, 1,
                                       tmpKey, &tmpKeySz, NULL, NULL, NULL, 0);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndExport(sz=1) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* wrappedKeySz=0: test KeyUnwrapAndCache path */
    ret = wh_Client_ObjectUnwrapCache(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                      WC_CIPHER_AES_GCM, dummyBuf, 0,
                                      WH_KEYID_ERASED, &wrappedKeyId);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndCache(sz=0) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* wrappedKeySz=1: test KeyUnwrapAndCache path */
    ret = wh_Client_ObjectUnwrapCache(client, WH_KEYTYPE_CRYPTO, WH_TEST_KEKID,
                                      WC_CIPHER_AES_GCM, dummyBuf, 1,
                                      WH_KEYID_ERASED, &wrappedKeyId);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndCache(sz=1) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

static int _AesGcm_TestDataUnwrapUnderflow(whClientContext* client)
{
    int      ret;
    uint8_t  dummyBuf[1] = {0};
    uint8_t  outBuf[32]  = {0};
    uint16_t outSz       = sizeof(outBuf);

    /* wrappedDataSz=0: must return WH_ERROR_BADARGS, not underflow */
    ret = wh_Client_ObjectUnwrapExport(client, WH_KEYTYPE_CRYPTO,
                               WH_TEST_KEKID, WC_CIPHER_AES_GCM,
                               dummyBuf, 0, outBuf, &outSz,
                               NULL, NULL, NULL, 0);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("DataUnwrap(sz=0) expected BADARGS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

    /* wrappedDataSz=1: must return WH_ERROR_BADARGS, not underflow */
    outSz = sizeof(outBuf);
    ret = wh_Client_ObjectUnwrapExport(client, WH_KEYTYPE_CRYPTO,
                               WH_TEST_KEKID, WC_CIPHER_AES_GCM,
                               dummyBuf, 1, outBuf, &outSz,
                               NULL, NULL, NULL, 0);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("DataUnwrap(sz=1) expected BADARGS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

#endif /* HAVE_AESGCM */

int whTest_Client_KeyWrap(whClientContext* client)
{
    int    ret = 0;
    WC_RNG rng[1];

    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_TestKeyWrap(client, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_TestKeyWrap %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestKeyUnwrapUnderflow(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestKeyUnwrapUnderflow %d\n",
                           ret);
        }
    }
#endif

    _CleanupServerKek(client);

    (void)wc_FreeRng(rng);
    return ret;
}

int whTest_Client_DataWrap(whClientContext* client)
{
    int ret = 0;

    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_TestDataWrap(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_TestDataWrap %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestDataUnwrapUnderflow(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestDataUnwrapUnderflow %d\n",
                           ret);
        }
    }
#endif

    _CleanupServerKek(client);

    return ret;
}

int whTest_KeyWrapClientConfig(whClientConfig* clientCfg)
{
    int             ret       = 0;
    whClientContext client[1] = {0};

    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, clientCfg));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_Init %d\n", ret);
        goto cleanup_and_exit;
    }

    ret = whTest_Client_KeyWrap(client);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to whTest_Client_KeyWrap %d\n", ret);
        goto cleanup_and_exit;
    }
    else {
        WH_TEST_PRINT("KEYWRAP TESTS SUCCESS\n");
    }

    ret = whTest_Client_DataWrap(client);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to whTest_Client_DataWrap %d\n", ret);
        goto cleanup_and_exit;
    }
    else {
        WH_TEST_PRINT("DATAWRAP TESTS SUCCESS\n");
    }

    /* Clean up used resources */
cleanup_and_exit:
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
#endif /* WOLFHSM_CFG_KEYWRAP */
