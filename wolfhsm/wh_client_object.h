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
 * wolfhsm/wh_client_object.h
 *
 * Client-side API for unified object operations.
 */

#ifndef WOLFHSM_WH_CLIENT_OBJECT_H_
#define WOLFHSM_WH_CLIENT_OBJECT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"

/* NVM Add */
int wh_Client_ObjectNvmAddRequest(whClientContext* c, uint16_t type,
    uint16_t id, whNvmAccess access, whNvmFlags flags,
    const uint8_t* label, uint16_t labelSz,
    const uint8_t* data, uint16_t dataSz);
int wh_Client_ObjectNvmAddResponse(whClientContext* c, int32_t* out_rc);
int wh_Client_ObjectNvmAdd(whClientContext* c, uint16_t type,
    uint16_t id, whNvmAccess access, whNvmFlags flags,
    const uint8_t* label, uint16_t labelSz,
    const uint8_t* data, uint16_t dataSz, int32_t* out_rc);

/* NVM Destroy */
int wh_Client_ObjectNvmDestroyRequest(whClientContext* c, uint16_t type,
    uint16_t id);
int wh_Client_ObjectNvmDestroyResponse(whClientContext* c, int32_t* out_rc);
int wh_Client_ObjectNvmDestroy(whClientContext* c, uint16_t type, uint16_t id,
    int32_t* out_rc);

/* NVM Read */
int wh_Client_ObjectNvmReadDataRequest(whClientContext* c, uint16_t type,
    uint16_t id, uint16_t offset, uint16_t data_len);
int wh_Client_ObjectNvmReadDataResponse(whClientContext* c, int32_t* out_rc,
    uint8_t* data, uint16_t* out_len);
int wh_Client_ObjectNvmReadData(whClientContext* c, uint16_t type,
    uint16_t id, uint16_t offset, uint16_t data_len,
    uint8_t* data, uint16_t* out_len, int32_t* out_rc);

/* Cache Add */
int wh_Client_ObjectCacheAddRequest(whClientContext* c, uint16_t type,
    uint16_t id, whNvmAccess access, whNvmFlags flags,
    const uint8_t* in, uint16_t inSz,
    const uint8_t* label, uint16_t labelSz);
int wh_Client_ObjectCacheAddResponse(whClientContext* c, uint16_t* out_id);
int wh_Client_ObjectCacheAdd(whClientContext* c, uint16_t type,
    uint16_t* inout_id, whNvmAccess access, whNvmFlags flags,
    const uint8_t* in, uint16_t inSz,
    const uint8_t* label, uint16_t labelSz);

/* Cache Load */
int wh_Client_ObjectCacheLoadRequest(whClientContext* c, uint16_t type,
    uint16_t id);
int wh_Client_ObjectCacheLoadResponse(whClientContext* c, int32_t* out_rc);
int wh_Client_ObjectCacheLoad(whClientContext* c, uint16_t type, uint16_t id);

/* Cache Evict */
int wh_Client_ObjectCacheEvictRequest(whClientContext* c, uint16_t type,
    uint16_t id);
int wh_Client_ObjectCacheEvictResponse(whClientContext* c, int32_t* out_rc);
int wh_Client_ObjectCacheEvict(whClientContext* c, uint16_t type, uint16_t id);

/* Cache Commit */
int wh_Client_ObjectCacheCommitRequest(whClientContext* c, uint16_t type,
    uint16_t id);
int wh_Client_ObjectCacheCommitResponse(whClientContext* c, int32_t* out_rc);
int wh_Client_ObjectCacheCommit(whClientContext* c, uint16_t type, uint16_t id);

/* Cache Export */
int wh_Client_ObjectCacheExportRequest(whClientContext* c, uint16_t type,
    uint16_t id);
int wh_Client_ObjectCacheExportResponse(whClientContext* c, int32_t* out_rc,
    uint8_t* label, uint16_t labelSz, uint8_t* out, uint16_t* outSz);
int wh_Client_ObjectCacheExport(whClientContext* c, uint16_t type, uint16_t id,
    uint8_t* label, uint16_t labelSz, uint8_t* out, uint16_t* outSz);

/* Cache Revoke */
int wh_Client_ObjectCacheRevokeRequest(whClientContext* c, uint16_t type,
    uint16_t id);
int wh_Client_ObjectCacheRevokeResponse(whClientContext* c, int32_t* out_rc);
int wh_Client_ObjectCacheRevoke(whClientContext* c, uint16_t type, uint16_t id);

#endif /* !WOLFHSM_WH_CLIENT_OBJECT_H_ */
