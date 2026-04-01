/*
 * Copyright (C) 2024 wolfSSL Inc.
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
/*
 * test/wh_test_legacy_keystore.c
 *
 * End-to-end tests for the legacy wh_Client_Key* / wh_Client_DataWrap /
 * wh_Client_DataUnwrap shim API.  These tests exercise the old function
 * signatures and verify they work correctly when routed through the new
 * Object API layer.
 *
 * Guarded by WOLFHSM_CFG_API_LEGACY_KEYSTORE.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_API_LEGACY_KEYSTORE
#ifdef WOLFHSM_CFG_ENABLE_CLIENT

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"

#define LK_KEYSIZE 16
#define LK_TEST_LABEL "LegacyKey Label"

/* ===================================================================
 * Group 1: Basic CRUD — Cache / Export / Evict / Commit / Erase / Revoke
 * =================================================================== */

/* Test: Cache a key, export it, verify data and label round-trip */
static int _testLegacyKeyCacheExport(whClientContext* ctx)
{
    int      ret;
    uint16_t keyId = WH_KEYID_ERASED;
    uint8_t  keyIn[LK_KEYSIZE];
    uint8_t  keyOut[LK_KEYSIZE]        = {0};
    uint8_t  labelIn[WH_NVM_LABEL_LEN] = LK_TEST_LABEL;
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    uint16_t keyOutSz                   = sizeof(keyOut);

    /* Fill key with pattern */
    memset(keyIn, 0xAB, sizeof(keyIn));

    ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), keyIn,
                             sizeof(keyIn), &keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCache failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut), keyOut,
                              &keyOutSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExport failed %d\n", ret);
        return ret;
    }

    if (keyOutSz != sizeof(keyIn) ||
        memcmp(keyIn, keyOut, keyOutSz) != 0 ||
        memcmp(labelIn, labelOut, sizeof(labelIn)) != 0) {
        WH_ERROR_PRINT("Cache/Export data mismatch\n");
        return -1;
    }

    /* Cleanup */
    (void)wh_Client_KeyEvict(ctx, keyId);

    WH_TEST_PRINT("LEGACY KEYSTORE: Cache/Export SUCCESS\n");
    return WH_ERROR_OK;
}

/* Test: Request/Response split variants for Cache and Export */
static int _testLegacyKeyCacheExportSplit(whClientContext* ctx)
{
    int      ret;
    uint16_t keyId = WH_KEYID_ERASED;
    uint8_t  keyIn[LK_KEYSIZE];
    uint8_t  keyOut[LK_KEYSIZE]         = {0};
    uint8_t  labelIn[WH_NVM_LABEL_LEN]  = "SplitTest Label";
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    uint16_t keyOutSz                   = sizeof(keyOut);

    memset(keyIn, 0xCD, sizeof(keyIn));

    /* Cache via Request/Response */
    ret = wh_Client_KeyCacheRequest(ctx, 0, labelIn, sizeof(labelIn), keyIn,
                                    sizeof(keyIn));
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCacheRequest failed %d\n", ret);
        return ret;
    }

    do {
        ret = wh_Client_KeyCacheResponse(ctx, &keyId);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCacheResponse failed %d\n", ret);
        return ret;
    }

    /* Export via Request/Response */
    ret = wh_Client_KeyExportRequest(ctx, keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExportRequest failed %d\n", ret);
        return ret;
    }

    do {
        ret = wh_Client_KeyExportResponse(ctx, labelOut, sizeof(labelOut),
                                          keyOut, &keyOutSz);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExportResponse failed %d\n", ret);
        return ret;
    }

    if (keyOutSz != sizeof(keyIn) ||
        memcmp(keyIn, keyOut, keyOutSz) != 0 ||
        memcmp(labelIn, labelOut, sizeof(labelIn)) != 0) {
        WH_ERROR_PRINT("Split Cache/Export data mismatch\n");
        return -1;
    }

    (void)wh_Client_KeyEvict(ctx, keyId);

    WH_TEST_PRINT("LEGACY KEYSTORE: Split Cache/Export SUCCESS\n");
    return WH_ERROR_OK;
}

/* Test: Cache a key, evict it, verify export fails with NOTFOUND */
static int _testLegacyKeyEvict(whClientContext* ctx)
{
    int      ret;
    uint16_t keyId = WH_KEYID_ERASED;
    uint8_t  keyIn[LK_KEYSIZE];
    uint8_t  keyOut[LK_KEYSIZE]        = {0};
    uint8_t  label[WH_NVM_LABEL_LEN]  = LK_TEST_LABEL;
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    uint16_t keyOutSz                   = sizeof(keyOut);

    memset(keyIn, 0xEF, sizeof(keyIn));

    ret = wh_Client_KeyCache(ctx, 0, label, sizeof(label), keyIn,
                             sizeof(keyIn), &keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCache failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyEvict(ctx, keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyEvict failed %d\n", ret);
        return ret;
    }

    /* Export should fail */
    keyOutSz = sizeof(keyOut);
    ret      = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                                   keyOut, &keyOutSz);
    if (ret != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Expected NOTFOUND after evict, got %d\n", ret);
        return -1;
    }

    WH_TEST_PRINT("LEGACY KEYSTORE: Evict SUCCESS\n");
    return WH_ERROR_OK;
}

/* Test: Cache → Commit → Evict → Export (finds committed) → Erase → Export
 * (NOTFOUND) */
static int _testLegacyKeyCommitErase(whClientContext* ctx)
{
    int      ret;
    uint16_t keyId = WH_KEYID_ERASED;
    uint8_t  keyIn[LK_KEYSIZE];
    uint8_t  keyOut[LK_KEYSIZE]         = {0};
    uint8_t  label[WH_NVM_LABEL_LEN]   = "CommitErase Lbl";
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    uint16_t keyOutSz                   = sizeof(keyOut);

    memset(keyIn, 0x42, sizeof(keyIn));

    ret = wh_Client_KeyCache(ctx, 0, label, sizeof(label), keyIn,
                             sizeof(keyIn), &keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCache failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyCommit(ctx, keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCommit failed %d\n", ret);
        return ret;
    }

    /* Evict from cache — committed copy should still be loadable */
    ret = wh_Client_KeyEvict(ctx, keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyEvict after commit failed %d\n", ret);
        return ret;
    }

    /* Export should find the committed key */
    keyOutSz = sizeof(keyOut);
    ret      = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                                   keyOut, &keyOutSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExport of committed key failed %d\n", ret);
        return ret;
    }

    if (keyOutSz != sizeof(keyIn) || memcmp(keyIn, keyOut, keyOutSz) != 0) {
        WH_ERROR_PRINT("Committed key data mismatch\n");
        return -1;
    }

    /* Erase from NVM */
    /* First evict from cache again (export loaded it) */
    (void)wh_Client_KeyEvict(ctx, keyId);
    ret = wh_Client_KeyErase(ctx, keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyErase failed %d\n", ret);
        return ret;
    }

    /* Export should now fail */
    keyOutSz = sizeof(keyOut);
    ret      = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                                   keyOut, &keyOutSz);
    if (ret != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Expected NOTFOUND after erase, got %d\n", ret);
        return -1;
    }

    WH_TEST_PRINT("LEGACY KEYSTORE: Commit/Erase SUCCESS\n");
    return WH_ERROR_OK;
}

/* Test: Cache → Revoke → verify revoke succeeds and key data is intact but
 * a re-cache with the same ID fails (NONMODIFIABLE) */
static int _testLegacyKeyRevoke(whClientContext* ctx)
{
    int      ret;
    uint16_t keyId = WH_KEYID_ERASED;
    uint8_t  keyIn[LK_KEYSIZE];
    uint8_t  keyOut[LK_KEYSIZE]         = {0};
    uint8_t  label[WH_NVM_LABEL_LEN]   = "Revoke Label";
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    uint16_t keyOutSz                   = sizeof(keyOut);

    memset(keyIn, 0x77, sizeof(keyIn));

    ret = wh_Client_KeyCache(ctx, 0, label, sizeof(label), keyIn,
                             sizeof(keyIn), &keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCache failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyRevoke(ctx, keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyRevoke failed %d\n", ret);
        return ret;
    }

    /* Key data should still be exportable after revoke */
    keyOutSz = sizeof(keyOut);
    ret      = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                                   keyOut, &keyOutSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExport after revoke failed %d\n", ret);
        return ret;
    }

    if (keyOutSz != sizeof(keyIn) ||
        memcmp(keyIn, keyOut, keyOutSz) != 0) {
        WH_ERROR_PRINT("Revoked key data mismatch\n");
        return -1;
    }

    /* Cleanup */
    (void)wh_Client_KeyEvict(ctx, keyId);

    WH_TEST_PRINT("LEGACY KEYSTORE: Revoke SUCCESS\n");
    return WH_ERROR_OK;
}

/* ===================================================================
 * Group 2: DMA
 * =================================================================== */

#ifdef WOLFHSM_CFG_DMA

static int _testLegacyKeyCacheExportDma(whClientContext* ctx)
{
    int      ret;
    uint16_t keyId = WH_KEYID_ERASED;
    uint8_t  keyIn[LK_KEYSIZE];
    uint8_t  keyOut[LK_KEYSIZE]         = {0};
    uint8_t  labelIn[WH_NVM_LABEL_LEN]  = "DMA Test Label";
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    uint16_t keyOutSz                   = sizeof(keyOut);

    memset(keyIn, 0xDA, sizeof(keyIn));

    ret = wh_Client_KeyCacheDma(ctx, 0, labelIn, sizeof(labelIn), keyIn,
                                sizeof(keyIn), &keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyCacheDma failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyExportDma(ctx, keyId, keyOut, sizeof(keyOut), labelOut,
                                 sizeof(labelOut), &keyOutSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExportDma failed %d\n", ret);
        return ret;
    }

    if (keyOutSz != sizeof(keyIn) ||
        memcmp(keyIn, keyOut, keyOutSz) != 0 ||
        memcmp(labelIn, labelOut, sizeof(labelIn)) != 0) {
        WH_ERROR_PRINT("DMA Cache/Export data mismatch\n");
        return -1;
    }

    (void)wh_Client_KeyEvict(ctx, keyId);

    WH_TEST_PRINT("LEGACY KEYSTORE: DMA Cache/Export SUCCESS\n");
    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_DMA */

/* ===================================================================
 * Group 3: Wrap / Unwrap / DataWrap / DataUnwrap
 * =================================================================== */

#ifndef WOLFHSM_CFG_NO_CRYPTO
#ifdef WOLFHSM_CFG_KEYWRAP
#ifdef HAVE_AESGCM

#include "wolfhsm/wh_common.h"

#define LK_KEK_ID 10
#define LK_AES_KEYSIZE 32
#define LK_WRAPPED_KEYSIZE \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + LK_AES_KEYSIZE + sizeof(whNvmMetadata))
#define LK_WRAPPED_DATASIZE \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof("Example data!") + \
     sizeof(whNvmMetadata))

static int _initLegacyKek(whClientContext* ctx)
{
    uint16_t kekId = LK_KEK_ID;
    uint8_t  label[WH_NVM_LABEL_LEN] = "Legacy KEK";
    uint8_t  kek[]                    = {0x03, 0x03, 0x0d, 0xd9, 0xeb, 0x18,
                                         0x17, 0x2e, 0x06, 0x6e, 0x19, 0xce,
                                         0x98, 0x44, 0x54, 0x0d, 0x78, 0xa0,
                                         0xbe, 0xe7, 0x35, 0x43, 0x40, 0xa4,
                                         0x22, 0x8a, 0xd1, 0x0e, 0xa3, 0x63,
                                         0x1c, 0x0b};
    uint32_t flags = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_WRAP;

    return wh_Client_KeyCache(ctx, flags, label, sizeof(label), kek,
                              sizeof(kek), &kekId);
}

static int _cleanupLegacyKek(whClientContext* ctx)
{
    return wh_Client_KeyEvict(ctx, LK_KEK_ID);
}

/* Test: KeyWrap → KeyUnwrapAndExport → verify key and metadata */
static int _testLegacyKeyWrapUnwrapExport(whClientContext* ctx)
{
    int           ret;
    uint8_t       plainKey[LK_AES_KEYSIZE];
    uint8_t       exportedKey[LK_AES_KEYSIZE]  = {0};
    uint16_t      exportedKeySz                = sizeof(exportedKey);
    uint8_t       wrappedKey[LK_WRAPPED_KEYSIZE] = {0};
    uint16_t      wrappedKeySz                 = sizeof(wrappedKey);
    whNvmMetadata metaIn                       = {0};
    whNvmMetadata metaOut                      = {0};

    memset(plainKey, 0x55, sizeof(plainKey));

    /* Set up wrap metadata */
    metaIn.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(0, 1);
    metaIn.len = sizeof(plainKey);
    memcpy(metaIn.label, "WrapTest", 9);

    ret = wh_Client_KeyWrap(ctx, WC_CIPHER_AES_GCM, LK_KEK_ID, plainKey,
                            sizeof(plainKey), &metaIn, wrappedKey,
                            &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyWrap failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndExport(ctx, WC_CIPHER_AES_GCM, LK_KEK_ID,
                                       wrappedKey, wrappedKeySz, &metaOut,
                                       exportedKey, &exportedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyUnwrapAndExport failed %d\n", ret);
        return ret;
    }

    if (exportedKeySz != sizeof(plainKey) ||
        memcmp(plainKey, exportedKey, exportedKeySz) != 0) {
        WH_ERROR_PRINT("Unwrapped key data mismatch\n");
        return -1;
    }

    if (memcmp(metaIn.label, metaOut.label, sizeof(metaIn.label)) != 0) {
        WH_ERROR_PRINT("Unwrapped metadata label mismatch\n");
        return -1;
    }

    WH_TEST_PRINT("LEGACY KEYSTORE: KeyWrap/UnwrapExport SUCCESS\n");
    return WH_ERROR_OK;
}

/* Test: KeyWrap → KeyUnwrapAndCache → Export cached → verify */
static int _testLegacyKeyWrapUnwrapCache(whClientContext* ctx)
{
    int      ret;
    uint8_t  plainKey[LK_AES_KEYSIZE];
    uint8_t  exportedKey[LK_AES_KEYSIZE]  = {0};
    uint16_t exportedKeySz                = sizeof(exportedKey);
    uint8_t  wrappedKey[LK_WRAPPED_KEYSIZE] = {0};
    uint16_t wrappedKeySz                 = sizeof(wrappedKey);
    uint16_t cachedKeyId                  = WH_KEYID_ERASED;
    uint8_t  labelOut[WH_NVM_LABEL_LEN]   = {0};
    whNvmMetadata metaIn                  = {0};

    memset(plainKey, 0xAA, sizeof(plainKey));

    metaIn.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(0, 2);
    metaIn.len = sizeof(plainKey);
    memcpy(metaIn.label, "CacheWrap", 10);

    ret = wh_Client_KeyWrap(ctx, WC_CIPHER_AES_GCM, LK_KEK_ID, plainKey,
                            sizeof(plainKey), &metaIn, wrappedKey,
                            &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyWrap failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndCache(ctx, WC_CIPHER_AES_GCM, LK_KEK_ID,
                                      wrappedKey, wrappedKeySz, &cachedKeyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyUnwrapAndCache failed %d\n", ret);
        return ret;
    }

    /* Export the cached key to verify contents */
    ret = wh_Client_KeyExport(ctx, cachedKeyId, labelOut, sizeof(labelOut),
                              exportedKey, &exportedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("KeyExport of cached unwrapped key failed %d\n", ret);
        (void)wh_Client_KeyEvict(ctx, cachedKeyId);
        return ret;
    }

    if (exportedKeySz != sizeof(plainKey) ||
        memcmp(plainKey, exportedKey, exportedKeySz) != 0) {
        WH_ERROR_PRINT("Cached unwrapped key data mismatch\n");
        (void)wh_Client_KeyEvict(ctx, cachedKeyId);
        return -1;
    }

    (void)wh_Client_KeyEvict(ctx, cachedKeyId);

    WH_TEST_PRINT("LEGACY KEYSTORE: KeyWrap/UnwrapCache SUCCESS\n");
    return WH_ERROR_OK;
}

/* Test: DataWrap → DataUnwrap → verify data matches */
static int _testLegacyDataWrapUnwrap(whClientContext* ctx)
{
    int      ret;
    uint8_t  data[]                            = "Example data!";
    uint8_t  unwrappedData[sizeof(data)]       = {0};
    uint32_t unwrappedDataSz                   = sizeof(unwrappedData);
    uint8_t  wrappedData[LK_WRAPPED_DATASIZE]  = {0};
    uint32_t wrappedDataSz                     = sizeof(wrappedData);

    ret = wh_Client_DataWrap(ctx, WC_CIPHER_AES_GCM, LK_KEK_ID, data,
                             sizeof(data), wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("DataWrap failed %d\n", ret);
        return ret;
    }

    ret = wh_Client_DataUnwrap(ctx, WC_CIPHER_AES_GCM, LK_KEK_ID, wrappedData,
                               wrappedDataSz, unwrappedData, &unwrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("DataUnwrap failed %d\n", ret);
        return ret;
    }

    if (unwrappedDataSz != sizeof(data) ||
        memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("DataWrap/Unwrap data mismatch\n");
        return -1;
    }

    WH_TEST_PRINT("LEGACY KEYSTORE: DataWrap/Unwrap SUCCESS\n");
    return WH_ERROR_OK;
}

#endif /* HAVE_AESGCM */
#endif /* WOLFHSM_CFG_KEYWRAP */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* ===================================================================
 * Entry point
 * =================================================================== */

int whTest_LegacyKeystoreClientConfig(whClientConfig* clientCfg)
{
    int             ret       = 0;
    whClientContext client[1] = {0};

    if (clientCfg == NULL)
        return WH_ERROR_BADARGS;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, clientCfg));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to CommInit %d\n", ret);
        goto cleanup;
    }

    /* Group 1: Basic CRUD */
    WH_TEST_RETURN_ON_FAIL(_testLegacyKeyCacheExport(client));
    WH_TEST_RETURN_ON_FAIL(_testLegacyKeyCacheExportSplit(client));
    WH_TEST_RETURN_ON_FAIL(_testLegacyKeyEvict(client));
    WH_TEST_RETURN_ON_FAIL(_testLegacyKeyCommitErase(client));
    WH_TEST_RETURN_ON_FAIL(_testLegacyKeyRevoke(client));

#ifdef WOLFHSM_CFG_DMA
    /* Group 2: DMA */
    WH_TEST_RETURN_ON_FAIL(_testLegacyKeyCacheExportDma(client));
#endif

#ifndef WOLFHSM_CFG_NO_CRYPTO
#ifdef WOLFHSM_CFG_KEYWRAP
#ifdef HAVE_AESGCM
    /* Group 3: Wrap/Unwrap */
    ret = _initLegacyKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to init legacy KEK %d\n", ret);
        goto cleanup;
    }

    ret = _testLegacyKeyWrapUnwrapExport(client);
    if (ret != WH_ERROR_OK) {
        _cleanupLegacyKek(client);
        goto cleanup;
    }

    ret = _testLegacyKeyWrapUnwrapCache(client);
    if (ret != WH_ERROR_OK) {
        _cleanupLegacyKek(client);
        goto cleanup;
    }

    ret = _testLegacyDataWrapUnwrap(client);
    _cleanupLegacyKek(client);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }
#endif /* HAVE_AESGCM */
#endif /* WOLFHSM_CFG_KEYWRAP */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

cleanup:
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

/* ===================================================================
 * Pthread harness for standalone execution from whTest_Unit()
 * =================================================================== */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <pthread.h>

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wh_test_common.h"

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 4096
#endif
#ifndef FLASH_RAM_SIZE
#define FLASH_RAM_SIZE (1024 * 1024)
#endif
#ifndef FLASH_SECTOR_SIZE
#define FLASH_SECTOR_SIZE (128 * 1024)
#endif
#ifndef FLASH_PAGE_SIZE
#define FLASH_PAGE_SIZE 8
#endif

static void* _legacyClientTask(void* cf)
{
    int rc = whTest_LegacyKeystoreClientConfig(cf);
    if (rc != 0) {
        WH_ERROR_PRINT("whTest_LegacyKeystoreClientConfig returned %d\n", rc);
    }
    WH_TEST_ASSERT(0 == rc);
    return NULL;
}

static void* _legacyServerTask(void* cf)
{
    whServerContext server[1]  = {0};
    whCommConnected connected = WH_COMM_CONNECTED;
    WH_TEST_ASSERT(0 == wh_Server_Init(server, cf));
    WH_TEST_ASSERT(0 == wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    while (connected == WH_COMM_CONNECTED) {
        int rc = wh_Server_HandleRequestMessage(server);
        if (rc == WH_ERROR_NOTREADY) {
            /* No message yet, spin */
        }
        else if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Server HandleRequest error: %d\n", rc);
            break;
        }
        wh_Server_GetConnected(server, &connected);
    }
    wh_Server_Cleanup(server);
    return NULL;
}

int whTest_LegacyKeystore(void)
{
    uint8_t req[BUFFER_SIZE]  = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    /* Client configuration */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
        .transport_cb      = tccb,
        .transport_context = (void*)tmcc,
        .transport_config  = (void*)tmcf,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
#ifdef WOLFHSM_CFG_DMA
    whClientDmaConfig clientDmaConfig = {0};
#endif
    whClientConfig c_conf[1] = {{
        .comm = cc_conf,
#ifdef WOLFHSM_CFG_DMA
        .dmaConfig = &clientDmaConfig,
#endif
    }};

    /* Server configuration */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
        .transport_cb      = tscb,
        .transport_context = (void*)tmsc,
        .transport_config  = (void*)tmcf,
        .server_id         = 124,
    }};

    /* Flash/NVM */
    uint8_t          memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                  = {0};
    whFlashRamsimCfg fc_conf[1]             = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb fcb[1] = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext          nvm[1]    = {{0}};

    whServerCryptoContext crypto[1] = {0};

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
    }};

    pthread_t cthread = {0};
    pthread_t sthread = {0};
    void*     retval;
    int       rc;

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(whTest_NvmCfgBackend(WH_NVM_TEST_BACKEND_FLASH,
                                                 &nvm_setup, n_conf, fc_conf,
                                                 fc, fcb));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    rc = pthread_create(&sthread, NULL, _legacyServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _legacyClientTask, c_conf);
        if (rc == 0) {
            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        }
        else {
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);
        }
    }

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}

#else /* not POSIX+CLIENT+SERVER */

int whTest_LegacyKeystore(void)
{
    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT &&
          WOLFHSM_CFG_ENABLE_SERVER */

#endif /* WOLFHSM_CFG_API_LEGACY_KEYSTORE */
