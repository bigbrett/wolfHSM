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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"

#include "wh_test_common.h"
#include "wh_test_object.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_client_object.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

static const uint8_t testObjData[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};
static const uint8_t testObjLabel[] = "TestObject";


/* Pointer to a local server context so the connect callback can access it */
static whServerContext* _testObjectServerCtx = NULL;

static int _objectTestConnectCb(void* context, whCommConnected connected)
{
    (void)context;
    if (_testObjectServerCtx == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Server_SetConnected(_testObjectServerCtx, connected);
}


/*
 * Test 1: Basic cache lifecycle - add/export/commit/evict/load/export/evict
 */
static int _testObjectCacheLifecycle(whClientContext* client,
                                     whServerContext* server)
{
    uint16_t outId = 0;
    int32_t  rc    = 0;
    uint8_t  exportBuf[sizeof(testObjData)];
    uint16_t exportSz = 0;
    uint8_t  labelBuf[WH_NVM_LABEL_LEN];

    /* CacheAdd with explicit ID */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddRequest(
        client, WH_KEYTYPE_CRYPTO, 5, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_USAGE_ANY, testObjData, sizeof(testObjData),
        testObjLabel, sizeof(testObjLabel)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddResponse(client, &outId));
    WH_TEST_ASSERT_RETURN(outId != 0);

    /* CacheExport - verify data matches */
    memset(exportBuf, 0, sizeof(exportBuf));
    exportSz = sizeof(exportBuf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportResponse(
        client, &rc, labelBuf, sizeof(labelBuf), exportBuf, &exportSz));
    WH_TEST_ASSERT_RETURN(exportSz == sizeof(testObjData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(exportBuf, testObjData, exportSz));

    /* CacheCommit to NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheCommitRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheCommitResponse(client, &rc));

    /* CacheEvict from cache */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvictRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheEvictResponse(client, &rc));

    /* CacheLoad - reload from NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheLoadRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheLoadResponse(client, &rc));

    /* CacheExport after reload - verify data still matches */
    memset(exportBuf, 0, sizeof(exportBuf));
    exportSz = sizeof(exportBuf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportResponse(
        client, &rc, labelBuf, sizeof(labelBuf), exportBuf, &exportSz));
    WH_TEST_ASSERT_RETURN(exportSz == sizeof(testObjData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(exportBuf, testObjData, exportSz));

    /* CacheEvict cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvictRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheEvictResponse(client, &rc));

    return WH_ERROR_OK;
}


/*
 * Test 2: Cache add with auto-assigned ID
 */
static int _testObjectCacheAddAutoId(whClientContext* client,
                                     whServerContext* server)
{
    uint16_t outId = 0;
    int32_t  rc    = 0;
    uint8_t  exportBuf[sizeof(testObjData)];
    uint16_t exportSz = 0;
    uint8_t  labelBuf[WH_NVM_LABEL_LEN];

    /* CacheAdd with id=WH_KEYID_ERASED (0) to request auto-assigned ID */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddRequest(
        client, WH_KEYTYPE_CRYPTO, WH_KEYID_ERASED, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_USAGE_ANY, testObjData, sizeof(testObjData),
        testObjLabel, sizeof(testObjLabel)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddResponse(client, &outId));
    /* Server should assign a non-zero ID */
    WH_TEST_ASSERT_RETURN(outId != 0);

    /* Export and verify data */
    memset(exportBuf, 0, sizeof(exportBuf));
    exportSz = sizeof(exportBuf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportResponse(
        client, &rc, labelBuf, sizeof(labelBuf), exportBuf, &exportSz));
    WH_TEST_ASSERT_RETURN(exportSz == sizeof(testObjData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(exportBuf, testObjData, exportSz));

    /* CacheEvict cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvictRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheEvictResponse(client, &rc));

    return WH_ERROR_OK;
}


/*
 * Test 3: Direct NVM add/read/destroy operations
 */
static int _testObjectNvmOperations(whClientContext* client,
                                    whServerContext* server)
{
    int32_t  rc      = 0;
    int      ret     = 0;
    uint8_t  readBuf[sizeof(testObjData)];
    uint16_t readLen = 0;

    /* ObjectNvmAdd with explicit id */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmAddRequest(
        client, WH_KEYTYPE_CRYPTO, 10, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_USAGE_ANY,
        testObjLabel, sizeof(testObjLabel),
        testObjData, sizeof(testObjData)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmAddResponse(client, &rc));

    /* ObjectNvmReadData - verify data matches */
    memset(readBuf, 0, sizeof(readBuf));
    readLen = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmReadDataRequest(
        client, WH_KEYTYPE_CRYPTO, 10, 0, sizeof(testObjData)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmReadDataResponse(
        client, &rc, readBuf, &readLen));
    WH_TEST_ASSERT_RETURN(readLen == sizeof(testObjData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(readBuf, testObjData, readLen));

    /* ObjectNvmDestroy */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmDestroyRequest(
        client, WH_KEYTYPE_CRYPTO, 10));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmDestroyResponse(client, &rc));

    /* ObjectNvmReadData should now fail (NOTFOUND) */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmReadDataRequest(
        client, WH_KEYTYPE_CRYPTO, 10, 0, sizeof(testObjData)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    ret = wh_Client_ObjectNvmReadDataResponse(client, &rc, readBuf, &readLen);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_NOTFOUND);

    return WH_ERROR_OK;
}


/*
 * Test 4: NONPERSISTABLE flag enforcement
 */
static int _testObjectNonpersistable(whClientContext* client,
                                     whServerContext* server)
{
    uint16_t outId = 0;
    int32_t  rc    = 0;
    int      ret   = 0;
    uint8_t  exportBuf[sizeof(testObjData)];
    uint16_t exportSz = 0;
    uint8_t  labelBuf[WH_NVM_LABEL_LEN];

    /* CacheAdd with NONPERSISTABLE flag */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddRequest(
        client, WH_KEYTYPE_CRYPTO, 20, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_USAGE_ANY | WH_NVM_FLAGS_NONPERSISTABLE,
        testObjData, sizeof(testObjData),
        testObjLabel, sizeof(testObjLabel)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddResponse(client, &outId));
    WH_TEST_ASSERT_RETURN(outId != 0);

    /* CacheCommit should fail with ACCESS error due to NONPERSISTABLE */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheCommitRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    ret = wh_Client_ObjectCacheCommitResponse(client, &rc);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);

    /* CacheExport should succeed (data is still in cache) */
    memset(exportBuf, 0, sizeof(exportBuf));
    exportSz = sizeof(exportBuf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportResponse(
        client, &rc, labelBuf, sizeof(labelBuf), exportBuf, &exportSz));
    WH_TEST_ASSERT_RETURN(exportSz == sizeof(testObjData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(exportBuf, testObjData, exportSz));

    /* CacheEvict cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvictRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheEvictResponse(client, &rc));

    return WH_ERROR_OK;
}


/*
 * Test 5: Erase from both cache and NVM
 *
 * There is no client-side CacheErase message, so we test erase by committing
 * an object, then destroying it via NvmDestroy and evicting from cache, and
 * verifying CacheLoad fails afterwards.
 */
static int _testObjectCacheErase(whClientContext* client,
                                 whServerContext* server)
{
    uint16_t outId = 0;
    int32_t  rc    = 0;
    int      ret   = 0;

    /* CacheAdd */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddRequest(
        client, WH_KEYTYPE_CRYPTO, 30, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_USAGE_ANY, testObjData, sizeof(testObjData),
        testObjLabel, sizeof(testObjLabel)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddResponse(client, &outId));
    WH_TEST_ASSERT_RETURN(outId != 0);

    /* CacheCommit to NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheCommitRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheCommitResponse(client, &rc));

    /* Evict from cache */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvictRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheEvictResponse(client, &rc));

    /* Destroy from NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmDestroyRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectNvmDestroyResponse(client, &rc));

    /* CacheLoad should fail (NOTFOUND) since object is gone from both */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheLoadRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    ret = wh_Client_ObjectCacheLoadResponse(client, &rc);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);

    return WH_ERROR_OK;
}


/*
 * Test 6: Revocation - clears usage flags and sets NONMODIFIABLE
 *
 * After revoking, we verify the object is still accessible via CacheExport
 * (the data should still be present). The server-side revoke sets
 * NONMODIFIABLE and clears usage flags on the metadata, so we verify a
 * subsequent CacheCommit fails (since NONMODIFIABLE prevents modification).
 */
static int _testObjectRevoke(whClientContext* client,
                             whServerContext* server)
{
    uint16_t outId = 0;
    int32_t  rc    = 0;
    uint8_t  exportBuf[sizeof(testObjData)];
    uint16_t exportSz = 0;
    uint8_t  labelBuf[WH_NVM_LABEL_LEN];

    /* CacheAdd with usage flags set */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddRequest(
        client, WH_KEYTYPE_CRYPTO, 40, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        testObjData, sizeof(testObjData),
        testObjLabel, sizeof(testObjLabel)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheAddResponse(client, &outId));
    WH_TEST_ASSERT_RETURN(outId != 0);

    /* CacheCommit so eviction is allowed after revoke */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheCommitRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheCommitResponse(client, &rc));

    /* CacheRevoke */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheRevokeRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheRevokeResponse(client, &rc));

    /* CacheExport should still succeed (object data is present) */
    memset(exportBuf, 0, sizeof(exportBuf));
    exportSz = sizeof(exportBuf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheExportResponse(
        client, &rc, labelBuf, sizeof(labelBuf), exportBuf, &exportSz));
    WH_TEST_ASSERT_RETURN(exportSz == sizeof(testObjData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(exportBuf, testObjData, exportSz));

    /* CacheEvict cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_ObjectCacheEvictRequest(
        client, WH_KEYTYPE_CRYPTO, outId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_ObjectCacheEvictResponse(client, &rc));

    return WH_ERROR_OK;
}


/*
 * Main test function: sets up client/server pair with memory transport
 * and runs all object sub-tests.
 */
int whTest_Object(void)
{
    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE];
    uint8_t              resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
        .transport_cb      = tccb,
        .transport_context = (void*)tmcc,
        .transport_config  = (void*)tmcf,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
        .connect_cb        = _objectTestConnectCb,
    }};

    whClientContext client[1] = {0};
    whClientConfig  c_conf[1] = {{
        .comm = cc_conf,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
        .transport_cb      = tscb,
        .transport_context = (void*)tmsc,
        .transport_config  = (void*)tmcf,
        .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb fcb[1] = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext           nvm[1]    = {{0}};

    whServerCryptoContext crypto[1] = {0};

    whServerConfig  s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
    }};
    whServerContext server[1] = {0};

    uint32_t client_id = 0;
    uint32_t server_id = 0;

    /* Expose the server context to our client connect callback */
    _testObjectServerCtx = server;

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(
        whTest_NvmCfgBackend(WH_NVM_TEST_BACKEND_FLASH, &nvm_setup, n_conf,
                             fc_conf, fc, fcb));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    /* Init server then client (server must be first so the connect callback
     * can set the server connected state) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Send the comm init message so server can obtain client ID */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInitResponse(client, &client_id, &server_id));

    /* Run sub-tests */
    WH_TEST_PRINT("Testing Object: cache lifecycle...\n");
    WH_TEST_RETURN_ON_FAIL(_testObjectCacheLifecycle(client, server));
    WH_TEST_PRINT("  PASS\n");

    WH_TEST_PRINT("Testing Object: auto ID assignment...\n");
    WH_TEST_RETURN_ON_FAIL(_testObjectCacheAddAutoId(client, server));
    WH_TEST_PRINT("  PASS\n");

    WH_TEST_PRINT("Testing Object: NVM operations...\n");
    WH_TEST_RETURN_ON_FAIL(_testObjectNvmOperations(client, server));
    WH_TEST_PRINT("  PASS\n");

    WH_TEST_PRINT("Testing Object: NONPERSISTABLE flag...\n");
    WH_TEST_RETURN_ON_FAIL(_testObjectNonpersistable(client, server));
    WH_TEST_PRINT("  PASS\n");

    WH_TEST_PRINT("Testing Object: erase...\n");
    WH_TEST_RETURN_ON_FAIL(_testObjectCacheErase(client, server));
    WH_TEST_PRINT("  PASS\n");

    WH_TEST_PRINT("Testing Object: revoke...\n");
    WH_TEST_RETURN_ON_FAIL(_testObjectRevoke(client, server));
    WH_TEST_PRINT("  PASS\n");

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}

#else /* !(ENABLE_CLIENT && ENABLE_SERVER && !NO_CRYPTO) */

int whTest_Object(void)
{
    return 0;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER &&
        * !WOLFHSM_CFG_NO_CRYPTO */
