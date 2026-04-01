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
 * wolfhsm/wh_message_object.h
 *
 * Message structures and translation functions for unified object operations.
 */

#ifndef WOLFHSM_WH_MESSAGE_OBJECT_H_
#define WOLFHSM_WH_MESSAGE_OBJECT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"

/*
 * Shared request/response types for common patterns
 */

/* Simple response: just a return code (4 bytes, pad to 8) */
typedef struct {
    int32_t  rc;
    uint8_t  WH_PAD[4];
} whMessageObject_SimpleResponse;

int wh_MessageObject_TranslateSimpleResponse(uint16_t magic,
        const whMessageObject_SimpleResponse* src,
        whMessageObject_SimpleResponse* dest);

/* Shared request for operations that only need type + id (8 bytes) */
typedef struct {
    uint16_t type;
    uint16_t id;
    uint8_t  WH_PAD[4];
} whMessageObject_TypeIdRequest;

int wh_MessageObject_TranslateTypeIdRequest(uint16_t magic,
        const whMessageObject_TypeIdRequest* src,
        whMessageObject_TypeIdRequest* dest);


/*
 * NVM Add (WH_OBJECT_NVM_ADD = 0x01)
 */

/* NVM Add Request (40 bytes) */
typedef struct {
    uint16_t type;
    uint16_t id;
    uint16_t access;
    uint16_t flags;
    uint16_t labelSz;
    uint8_t  WH_PAD[6];
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Data follows */
} whMessageObject_NvmAddRequest;

int wh_MessageObject_TranslateNvmAddRequest(uint16_t magic,
        const whMessageObject_NvmAddRequest* src,
        whMessageObject_NvmAddRequest* dest);

/* NVM Add Response: use SimpleResponse */


/*
 * NVM Destroy (WH_OBJECT_NVM_DESTROY = 0x02)
 */

/* NVM Destroy Request: use TypeIdRequest */

/* NVM Destroy Response: use SimpleResponse */


/*
 * NVM Read (WH_OBJECT_NVM_READ = 0x03)
 */

/* NVM Read Request (8 bytes) */
typedef struct {
    uint16_t type;
    uint16_t id;
    uint16_t offset;
    uint16_t data_len;
} whMessageObject_NvmReadRequest;

int wh_MessageObject_TranslateNvmReadRequest(uint16_t magic,
        const whMessageObject_NvmReadRequest* src,
        whMessageObject_NvmReadRequest* dest);

/* NVM Read Response (8 bytes) */
typedef struct {
    int32_t  rc;
    uint8_t  WH_PAD[4];
    /* Data follows */
} whMessageObject_NvmReadResponse;

int wh_MessageObject_TranslateNvmReadResponse(uint16_t magic,
        const whMessageObject_NvmReadResponse* src,
        whMessageObject_NvmReadResponse* dest);


/*
 * NVM GetAvailable (WH_OBJECT_NVM_GETAVAIL = 0x04)
 */

/* NVM GetAvailable Request (4 bytes, pad to 8) */
typedef struct {
    uint16_t type;
    uint8_t  WH_PAD[2];
} whMessageObject_NvmGetAvailRequest;

int wh_MessageObject_TranslateNvmGetAvailRequest(uint16_t magic,
        const whMessageObject_NvmGetAvailRequest* src,
        whMessageObject_NvmGetAvailRequest* dest);

/* NVM GetAvailable Response (12 bytes) */
typedef struct {
    int32_t  rc;
    uint32_t avail_size;
    uint16_t avail_objects;
    uint8_t  WH_PAD[2];
} whMessageObject_NvmGetAvailResponse;

int wh_MessageObject_TranslateNvmGetAvailResponse(uint16_t magic,
        const whMessageObject_NvmGetAvailResponse* src,
        whMessageObject_NvmGetAvailResponse* dest);


/*
 * NVM Iterate (WH_OBJECT_NVM_ITERATE = 0x05)
 */

/* NVM Iterate Request (8 bytes) */
typedef struct {
    uint16_t type;
    uint16_t startId;
    uint16_t access;
    uint16_t flags;
} whMessageObject_NvmIterateRequest;

int wh_MessageObject_TranslateNvmIterateRequest(uint16_t magic,
        const whMessageObject_NvmIterateRequest* src,
        whMessageObject_NvmIterateRequest* dest);

/* NVM Iterate Response (8 bytes) */
typedef struct {
    int32_t  rc;
    uint16_t count;
    uint16_t id;
} whMessageObject_NvmIterateResponse;

int wh_MessageObject_TranslateNvmIterateResponse(uint16_t magic,
        const whMessageObject_NvmIterateResponse* src,
        whMessageObject_NvmIterateResponse* dest);


/*
 * Cache Add (WH_OBJECT_CACHE_ADD = 0x10)
 */

/* Cache Add Request (40 bytes) */
typedef struct {
    uint16_t type;
    uint16_t id;
    uint16_t access;
    uint16_t flags;
    uint32_t sz;
    uint32_t labelSz;
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Data follows */
} whMessageObject_CacheAddRequest;

int wh_MessageObject_TranslateCacheAddRequest(uint16_t magic,
        const whMessageObject_CacheAddRequest* src,
        whMessageObject_CacheAddRequest* dest);

/* Cache Add Response (8 bytes) */
typedef struct {
    int32_t  rc;
    uint16_t id;
    uint8_t  WH_PAD[2];
} whMessageObject_CacheAddResponse;

int wh_MessageObject_TranslateCacheAddResponse(uint16_t magic,
        const whMessageObject_CacheAddResponse* src,
        whMessageObject_CacheAddResponse* dest);


/*
 * Cache Load (WH_OBJECT_CACHE_LOAD = 0x11)
 */

/* Cache Load Request: use TypeIdRequest */

/* Cache Load Response: use SimpleResponse */


/*
 * Cache Evict (WH_OBJECT_CACHE_EVICT = 0x12)
 */

/* Cache Evict Request: use TypeIdRequest */

/* Cache Evict Response: use SimpleResponse */


/*
 * Cache Commit (WH_OBJECT_CACHE_COMMIT = 0x13)
 */

/* Cache Commit Request: use TypeIdRequest */

/* Cache Commit Response: use SimpleResponse */


/*
 * Cache Export (WH_OBJECT_CACHE_EXPORT = 0x14)
 */

/* Cache Export Request: use TypeIdRequest */

/* Cache Export Response (32 bytes) */
typedef struct {
    int32_t  rc;
    uint32_t len;
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Data follows */
} whMessageObject_CacheExportResponse;

int wh_MessageObject_TranslateCacheExportResponse(uint16_t magic,
        const whMessageObject_CacheExportResponse* src,
        whMessageObject_CacheExportResponse* dest);


/*
 * Cache Revoke (WH_OBJECT_CACHE_REVOKE = 0x15)
 */

/* Cache Revoke Request: use TypeIdRequest */

/* Cache Revoke Response: use SimpleResponse */


/*
 * Wrap (WH_OBJECT_WRAP = 0x20)
 */

/* Wrap Request (40 bytes) */
typedef struct {
    uint16_t type;
    uint16_t serverKekId;
    uint16_t cipherType;
    uint16_t keySz;
    uint16_t access;
    uint16_t flags;
    uint16_t ownerId;  /* Client-format ID indicating ownership (use
                        * WH_KEYID_CLIENT_GLOBAL_FLAG for global) */
    uint8_t  WH_PAD[2];
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Key data follows */
} whMessageObject_WrapRequest;

int wh_MessageObject_TranslateWrapRequest(uint16_t magic,
        const whMessageObject_WrapRequest* src,
        whMessageObject_WrapRequest* dest);

/* Wrap Response (8 bytes) */
typedef struct {
    int32_t  rc;
    uint16_t wrappedSz;
    uint8_t  WH_PAD[2];
    /* Wrapped data follows */
} whMessageObject_WrapResponse;

int wh_MessageObject_TranslateWrapResponse(uint16_t magic,
        const whMessageObject_WrapResponse* src,
        whMessageObject_WrapResponse* dest);


/*
 * Unwrap Cache (WH_OBJECT_UNWRAP_CACHE = 0x21)
 */

/* Unwrap Cache Request (12 bytes) */
typedef struct {
    uint16_t type;
    uint16_t serverKekId;
    uint16_t cipherType;
    uint16_t wrappedSz;
    uint16_t requestedId;
    uint8_t  WH_PAD[2];
    /* Wrapped data follows */
} whMessageObject_UnwrapCacheRequest;

int wh_MessageObject_TranslateUnwrapCacheRequest(uint16_t magic,
        const whMessageObject_UnwrapCacheRequest* src,
        whMessageObject_UnwrapCacheRequest* dest);

/* Unwrap Cache Response (8 bytes) */
typedef struct {
    int32_t  rc;
    uint16_t id;
    uint8_t  WH_PAD[2];
} whMessageObject_UnwrapCacheResponse;

int wh_MessageObject_TranslateUnwrapCacheResponse(uint16_t magic,
        const whMessageObject_UnwrapCacheResponse* src,
        whMessageObject_UnwrapCacheResponse* dest);


/*
 * Unwrap Export (WH_OBJECT_UNWRAP_EXPORT = 0x22)
 */

/* Unwrap Export Request (8 bytes) */
typedef struct {
    uint16_t type;
    uint16_t serverKekId;
    uint16_t cipherType;
    uint16_t wrappedSz;
    /* Wrapped data follows */
} whMessageObject_UnwrapExportRequest;

int wh_MessageObject_TranslateUnwrapExportRequest(uint16_t magic,
        const whMessageObject_UnwrapExportRequest* src,
        whMessageObject_UnwrapExportRequest* dest);

/* Unwrap Export Response (40 bytes) */
typedef struct {
    int32_t  rc;
    uint16_t keySz;
    uint16_t access;
    uint16_t flags;
    uint8_t  WH_PAD[2];
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Key data follows */
} whMessageObject_UnwrapExportResponse;

int wh_MessageObject_TranslateUnwrapExportResponse(uint16_t magic,
        const whMessageObject_UnwrapExportResponse* src,
        whMessageObject_UnwrapExportResponse* dest);


/*
 * DMA variants
 *
 * WH_OBJECT_NVM_ADD_DMA       = 0x30
 * WH_OBJECT_NVM_READ_DMA      = 0x31
 * WH_OBJECT_CACHE_ADD_DMA     = 0x32
 * WH_OBJECT_CACHE_EXPORT_DMA  = 0x33
 */

#ifdef WOLFHSM_CFG_DMA

/* DMA buffer structure */
typedef struct {
    uint64_t addr;
    uint64_t sz;
} whMessageObject_DmaBuffer;

/* DMA address status structure */
typedef struct {
    /* If packet->rc == WH_ERROR_ACCESS, this field will contain the offending
     * address/size pair. Invalid otherwise. */
    whMessageObject_DmaBuffer badAddr;
} whMessageObject_DmaAddrStatus;

/*
 * Cache Add DMA (WH_OBJECT_CACHE_ADD_DMA = 0x32)
 */

/* Cache Add DMA Request */
typedef struct {
    whMessageObject_DmaBuffer obj;   /* Client memory buffer containing data */
    uint16_t type;
    uint16_t id;
    uint16_t access;
    uint16_t flags;
    uint32_t labelSz;
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint8_t  WH_PAD[4];
} whMessageObject_CacheAddDmaRequest;

/* Cache Add DMA Response */
typedef struct {
    whMessageObject_DmaAddrStatus dmaAddrStatus;
    int32_t  rc;
    uint16_t id;
    uint8_t  WH_PAD[2];
} whMessageObject_CacheAddDmaResponse;

int wh_MessageObject_TranslateCacheAddDmaRequest(uint16_t magic,
        const whMessageObject_CacheAddDmaRequest* src,
        whMessageObject_CacheAddDmaRequest* dest);
int wh_MessageObject_TranslateCacheAddDmaResponse(uint16_t magic,
        const whMessageObject_CacheAddDmaResponse* src,
        whMessageObject_CacheAddDmaResponse* dest);


/*
 * Cache Export DMA (WH_OBJECT_CACHE_EXPORT_DMA = 0x33)
 */

/* Cache Export DMA Request */
typedef struct {
    whMessageObject_DmaBuffer obj;   /* Client memory buffer to receive data */
    uint16_t type;
    uint16_t id;
    uint8_t  WH_PAD[4];
} whMessageObject_CacheExportDmaRequest;

/* Cache Export DMA Response */
typedef struct {
    whMessageObject_DmaAddrStatus dmaAddrStatus;
    int32_t  rc;
    uint32_t len;
    uint8_t  label[WH_NVM_LABEL_LEN];
} whMessageObject_CacheExportDmaResponse;

int wh_MessageObject_TranslateCacheExportDmaRequest(uint16_t magic,
        const whMessageObject_CacheExportDmaRequest* src,
        whMessageObject_CacheExportDmaRequest* dest);
int wh_MessageObject_TranslateCacheExportDmaResponse(uint16_t magic,
        const whMessageObject_CacheExportDmaResponse* src,
        whMessageObject_CacheExportDmaResponse* dest);

#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_WH_MESSAGE_OBJECT_H_ */
