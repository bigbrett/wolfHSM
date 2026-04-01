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
 * src/wh_message_object.c
 *
 * Message translation functions for unified object operations.
 */

#include "wolfhsm/wh_message_object.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include <string.h>

/* Simple Response translation */
int wh_MessageObject_TranslateSimpleResponse(
    uint16_t magic, const whMessageObject_SimpleResponse* src,
    whMessageObject_SimpleResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

/* TypeId Request translation (shared by Load, Evict, Commit, Revoke, Destroy)
 */
int wh_MessageObject_TranslateTypeIdRequest(
    uint16_t magic, const whMessageObject_TypeIdRequest* src,
    whMessageObject_TypeIdRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, id);
    return 0;
}

/* NVM Add Request translation */
int wh_MessageObject_TranslateNvmAddRequest(
    uint16_t magic, const whMessageObject_NvmAddRequest* src,
    whMessageObject_NvmAddRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T16(magic, dest, src, labelSz);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* NVM Read Request translation */
int wh_MessageObject_TranslateNvmReadRequest(
    uint16_t magic, const whMessageObject_NvmReadRequest* src,
    whMessageObject_NvmReadRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, offset);
    WH_T16(magic, dest, src, data_len);
    return 0;
}

/* NVM Read Response translation */
int wh_MessageObject_TranslateNvmReadResponse(
    uint16_t magic, const whMessageObject_NvmReadResponse* src,
    whMessageObject_NvmReadResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

/* NVM GetAvailable Request translation */
int wh_MessageObject_TranslateNvmGetAvailRequest(
    uint16_t magic, const whMessageObject_NvmGetAvailRequest* src,
    whMessageObject_NvmGetAvailRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    return 0;
}

/* NVM GetAvailable Response translation */
int wh_MessageObject_TranslateNvmGetAvailResponse(
    uint16_t magic, const whMessageObject_NvmGetAvailResponse* src,
    whMessageObject_NvmGetAvailResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, avail_size);
    WH_T16(magic, dest, src, avail_objects);
    return 0;
}

/* NVM Iterate Request translation */
int wh_MessageObject_TranslateNvmIterateRequest(
    uint16_t magic, const whMessageObject_NvmIterateRequest* src,
    whMessageObject_NvmIterateRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, startId);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    return 0;
}

/* NVM Iterate Response translation */
int wh_MessageObject_TranslateNvmIterateResponse(
    uint16_t magic, const whMessageObject_NvmIterateResponse* src,
    whMessageObject_NvmIterateResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, count);
    WH_T16(magic, dest, src, id);
    return 0;
}

/* Cache Add Request translation */
int wh_MessageObject_TranslateCacheAddRequest(
    uint16_t magic, const whMessageObject_CacheAddRequest* src,
    whMessageObject_CacheAddRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, labelSz);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* Cache Add Response translation */
int wh_MessageObject_TranslateCacheAddResponse(
    uint16_t magic, const whMessageObject_CacheAddResponse* src,
    whMessageObject_CacheAddResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, id);
    return 0;
}

/* Cache Export Response translation */
int wh_MessageObject_TranslateCacheExportResponse(
    uint16_t magic, const whMessageObject_CacheExportResponse* src,
    whMessageObject_CacheExportResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, len);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* Wrap Request translation */
int wh_MessageObject_TranslateWrapRequest(
    uint16_t magic, const whMessageObject_WrapRequest* src,
    whMessageObject_WrapRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, serverKekId);
    WH_T16(magic, dest, src, cipherType);
    WH_T16(magic, dest, src, keySz);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T16(magic, dest, src, ownerId);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* Wrap Response translation */
int wh_MessageObject_TranslateWrapResponse(
    uint16_t magic, const whMessageObject_WrapResponse* src,
    whMessageObject_WrapResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, wrappedSz);
    return 0;
}

/* Unwrap Cache Request translation */
int wh_MessageObject_TranslateUnwrapCacheRequest(
    uint16_t magic, const whMessageObject_UnwrapCacheRequest* src,
    whMessageObject_UnwrapCacheRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, serverKekId);
    WH_T16(magic, dest, src, cipherType);
    WH_T16(magic, dest, src, wrappedSz);
    WH_T16(magic, dest, src, requestedId);
    return 0;
}

/* Unwrap Cache Response translation */
int wh_MessageObject_TranslateUnwrapCacheResponse(
    uint16_t magic, const whMessageObject_UnwrapCacheResponse* src,
    whMessageObject_UnwrapCacheResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, id);
    return 0;
}

/* Unwrap Export Request translation */
int wh_MessageObject_TranslateUnwrapExportRequest(
    uint16_t magic, const whMessageObject_UnwrapExportRequest* src,
    whMessageObject_UnwrapExportRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, serverKekId);
    WH_T16(magic, dest, src, cipherType);
    WH_T16(magic, dest, src, wrappedSz);
    return 0;
}

/* Unwrap Export Response translation */
int wh_MessageObject_TranslateUnwrapExportResponse(
    uint16_t magic, const whMessageObject_UnwrapExportResponse* src,
    whMessageObject_UnwrapExportResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, keySz);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

#ifdef WOLFHSM_CFG_DMA

/* Cache Add DMA Request translation */
int wh_MessageObject_TranslateCacheAddDmaRequest(
    uint16_t magic, const whMessageObject_CacheAddDmaRequest* src,
    whMessageObject_CacheAddDmaRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, obj.addr);
    WH_T64(magic, dest, src, obj.sz);
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T32(magic, dest, src, labelSz);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* Cache Add DMA Response translation */
int wh_MessageObject_TranslateCacheAddDmaResponse(
    uint16_t magic, const whMessageObject_CacheAddDmaResponse* src,
    whMessageObject_CacheAddDmaResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, dmaAddrStatus.badAddr.addr);
    WH_T64(magic, dest, src, dmaAddrStatus.badAddr.sz);
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, id);
    return 0;
}

/* Cache Export DMA Request translation */
int wh_MessageObject_TranslateCacheExportDmaRequest(
    uint16_t magic, const whMessageObject_CacheExportDmaRequest* src,
    whMessageObject_CacheExportDmaRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, obj.addr);
    WH_T64(magic, dest, src, obj.sz);
    WH_T16(magic, dest, src, type);
    WH_T16(magic, dest, src, id);
    return 0;
}

/* Cache Export DMA Response translation */
int wh_MessageObject_TranslateCacheExportDmaResponse(
    uint16_t magic, const whMessageObject_CacheExportDmaResponse* src,
    whMessageObject_CacheExportDmaResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, dmaAddrStatus.badAddr.addr);
    WH_T64(magic, dest, src, dmaAddrStatus.badAddr.sz);
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, len);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

#endif /* WOLFHSM_CFG_DMA */
