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
/*
 * src/wh_client_object.c
 *
 * Client-side implementation for unified object operations.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

/* Components */
#include "wolfhsm/wh_comm.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_object.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_object.h"


/*
 * NVM Add
 */

int wh_Client_ObjectNvmAddRequest(whClientContext* c, uint16_t type,
                                   uint16_t id, whNvmAccess access,
                                   whNvmFlags flags,
                                   const uint8_t* label, uint16_t labelSz,
                                   const uint8_t* data, uint16_t dataSz)
{
    whMessageObject_NvmAddRequest* req = NULL;
    uint8_t* packData;
    uint16_t capSz;

    if (c == NULL || data == NULL || dataSz == 0 ||
        sizeof(*req) + dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_NvmAddRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    packData = (uint8_t*)(req + 1);

    req->type   = type;
    req->id     = id;
    req->access = access;
    req->flags  = flags;

    if (label != NULL) {
        capSz = (labelSz > WH_NVM_LABEL_LEN) ? WH_NVM_LABEL_LEN : labelSz;
        req->labelSz = capSz;
        memcpy(req->label, label, capSz);
    }

    memcpy(packData, data, dataSz);

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_NVM_ADD,
                                 sizeof(*req) + dataSz, (uint8_t*)req);
}

int wh_Client_ObjectNvmAddResponse(whClientContext* c, int32_t* out_rc)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);
    if (ret == WH_ERROR_OK) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectNvmAdd(whClientContext* c, uint16_t type,
                            uint16_t id, whNvmAccess access, whNvmFlags flags,
                            const uint8_t* label, uint16_t labelSz,
                            const uint8_t* data, uint16_t dataSz,
                            int32_t* out_rc)
{
    int ret;

    ret = wh_Client_ObjectNvmAddRequest(c, type, id, access, flags,
                                         label, labelSz, data, dataSz);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectNvmAddResponse(c, out_rc);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * NVM Destroy
 */

int wh_Client_ObjectNvmDestroyRequest(whClientContext* c, uint16_t type,
                                       uint16_t id)
{
    whMessageObject_TypeIdRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_TypeIdRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->id   = id;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_NVM_DESTROY,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectNvmDestroyResponse(whClientContext* c, int32_t* out_rc)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);
    if (ret == WH_ERROR_OK) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectNvmDestroy(whClientContext* c, uint16_t type, uint16_t id,
                                int32_t* out_rc)
{
    int ret;

    ret = wh_Client_ObjectNvmDestroyRequest(c, type, id);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectNvmDestroyResponse(c, out_rc);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * NVM Read
 */

int wh_Client_ObjectNvmReadDataRequest(whClientContext* c, uint16_t type,
                                        uint16_t id, uint16_t offset,
                                        uint16_t data_len)
{
    whMessageObject_NvmReadRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_NvmReadRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type     = type;
    req->id       = id;
    req->offset   = offset;
    req->data_len = data_len;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_NVM_READ,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectNvmReadDataResponse(whClientContext* c, int32_t* out_rc,
                                         uint8_t* data, uint16_t* out_len)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_NvmReadResponse* resp = NULL;
    uint8_t* packOut;
    uint16_t dataLen;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageObject_NvmReadResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else {
            /* Data length is total message size minus the response header */
            dataLen = size - sizeof(*resp);
            if (data != NULL && dataLen > 0) {
                memcpy(data, packOut, dataLen);
            }
            if (out_len != NULL) {
                *out_len = dataLen;
            }
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectNvmReadData(whClientContext* c, uint16_t type,
                                 uint16_t id, uint16_t offset,
                                 uint16_t data_len, uint8_t* data,
                                 uint16_t* out_len, int32_t* out_rc)
{
    int ret;

    ret = wh_Client_ObjectNvmReadDataRequest(c, type, id, offset, data_len);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectNvmReadDataResponse(c, out_rc, data,
                                                       out_len);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * Cache Add
 */

int wh_Client_ObjectCacheAddRequest(whClientContext* c, uint16_t type,
                                     uint16_t id, whNvmAccess access,
                                     whNvmFlags flags,
                                     const uint8_t* in, uint16_t inSz,
                                     const uint8_t* label, uint16_t labelSz)
{
    whMessageObject_CacheAddRequest* req = NULL;
    uint8_t* packIn;
    uint16_t capSz;

    if (c == NULL || in == NULL || inSz == 0 ||
        sizeof(*req) + inSz > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_CacheAddRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    packIn = (uint8_t*)(req + 1);

    req->type   = type;
    req->id     = id;
    req->access = access;
    req->flags  = flags;
    req->sz     = inSz;

    if (label != NULL) {
        capSz = (labelSz > WH_NVM_LABEL_LEN) ? WH_NVM_LABEL_LEN : labelSz;
        req->labelSz = capSz;
        memcpy(req->label, label, capSz);
    }

    memcpy(packIn, in, inSz);

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_CACHE_ADD,
                                 sizeof(*req) + inSz, (uint8_t*)req);
}

int wh_Client_ObjectCacheAddResponse(whClientContext* c, uint16_t* out_id)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_CacheAddResponse* resp = NULL;

    if (c == NULL || out_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageObject_CacheAddResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else {
            *out_id = resp->id;
        }
    }

    return ret;
}

int wh_Client_ObjectCacheAdd(whClientContext* c, uint16_t type,
                              uint16_t* inout_id, whNvmAccess access,
                              whNvmFlags flags,
                              const uint8_t* in, uint16_t inSz,
                              const uint8_t* label, uint16_t labelSz)
{
    int ret;

    if (inout_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_ObjectCacheAddRequest(c, type, *inout_id, access, flags,
                                           in, inSz, label, labelSz);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectCacheAddResponse(c, inout_id);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * Cache Load
 */

int wh_Client_ObjectCacheLoadRequest(whClientContext* c, uint16_t type,
                                      uint16_t id)
{
    whMessageObject_TypeIdRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_TypeIdRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->id   = id;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_CACHE_LOAD,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectCacheLoadResponse(whClientContext* c, int32_t* out_rc)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);
    if (ret == WH_ERROR_OK) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectCacheLoad(whClientContext* c, uint16_t type, uint16_t id)
{
    int ret;

    ret = wh_Client_ObjectCacheLoadRequest(c, type, id);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectCacheLoadResponse(c, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * Cache Evict
 */

int wh_Client_ObjectCacheEvictRequest(whClientContext* c, uint16_t type,
                                       uint16_t id)
{
    whMessageObject_TypeIdRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_TypeIdRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->id   = id;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_CACHE_EVICT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectCacheEvictResponse(whClientContext* c, int32_t* out_rc)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);
    if (ret == WH_ERROR_OK) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectCacheEvict(whClientContext* c, uint16_t type, uint16_t id)
{
    int ret;

    ret = wh_Client_ObjectCacheEvictRequest(c, type, id);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectCacheEvictResponse(c, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * Cache Commit
 */

int wh_Client_ObjectCacheCommitRequest(whClientContext* c, uint16_t type,
                                        uint16_t id)
{
    whMessageObject_TypeIdRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_TypeIdRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->id   = id;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_CACHE_COMMIT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectCacheCommitResponse(whClientContext* c, int32_t* out_rc)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);
    if (ret == WH_ERROR_OK) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectCacheCommit(whClientContext* c, uint16_t type, uint16_t id)
{
    int ret;

    ret = wh_Client_ObjectCacheCommitRequest(c, type, id);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectCacheCommitResponse(c, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * Cache Export
 */

int wh_Client_ObjectCacheExportRequest(whClientContext* c, uint16_t type,
                                        uint16_t id)
{
    whMessageObject_TypeIdRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_TypeIdRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->id   = id;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_CACHE_EXPORT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectCacheExportResponse(whClientContext* c, int32_t* out_rc,
                                         uint8_t* label, uint16_t labelSz,
                                         uint8_t* out, uint16_t* outSz)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_CacheExportResponse* resp = NULL;
    uint8_t* packOut;
    uint16_t capSz;

    if (c == NULL || outSz == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageObject_CacheExportResponse*)
        wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else {
            if (out == NULL) {
                *outSz = resp->len;
            }
            else if (*outSz < resp->len) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(out, packOut, resp->len);
                *outSz = resp->len;
            }
            if (label != NULL) {
                capSz = (labelSz > sizeof(resp->label))
                    ? sizeof(resp->label) : labelSz;
                memcpy(label, resp->label, capSz);
            }
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectCacheExport(whClientContext* c, uint16_t type, uint16_t id,
                                 uint8_t* label, uint16_t labelSz,
                                 uint8_t* out, uint16_t* outSz)
{
    int ret;

    ret = wh_Client_ObjectCacheExportRequest(c, type, id);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectCacheExportResponse(c, NULL, label, labelSz,
                                                       out, outSz);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}


/*
 * Cache Revoke
 */

int wh_Client_ObjectCacheRevokeRequest(whClientContext* c, uint16_t type,
                                        uint16_t id)
{
    whMessageObject_TypeIdRequest* req = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageObject_TypeIdRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->id   = id;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_OBJECT,
                                 WH_OBJECT_CACHE_REVOKE,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_ObjectCacheRevokeResponse(whClientContext* c, int32_t* out_rc)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageObject_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);
    if (ret == WH_ERROR_OK) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    if (out_rc != NULL) {
        *out_rc = (ret == WH_ERROR_OK) ? 0 : ret;
    }

    return ret;
}

int wh_Client_ObjectCacheRevoke(whClientContext* c, uint16_t type, uint16_t id)
{
    int ret;

    ret = wh_Client_ObjectCacheRevokeRequest(c, type, id);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_ObjectCacheRevokeResponse(c, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
