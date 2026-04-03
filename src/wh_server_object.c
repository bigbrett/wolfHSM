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
 * src/wh_server_object.c
 *
 * Server-side Object management layer implementation.
 * Generalizes wh_server_keystore.c for the unified Object model.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_SERVER)

/* System libraries */
#include <stdint.h>
#include <stddef.h> /* For NULL */
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#ifdef WOLFHSM_CFG_KEYWRAP
#include "wolfssl/wolfcrypt/aes.h"
#endif

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_object.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_log.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_server_she.h"
#endif

#include "wolfhsm/wh_server_object.h"

/*
 * Forward declaration
 */
static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta);

/*
 * Static helper functions
 */

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/*
 * @brief Check if keyId represents a global key (USER == 0)
 */
static int _IsGlobalKey(whKeyId keyId)
{
    return (WH_KEYID_USER(keyId) == WH_KEYUSER_GLOBAL);
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/*
 * @brief Get the appropriate cache context based on keyId
 *
 * When WOLFHSM_CFG_GLOBAL_KEYS is enabled, routes to global cache if keyId
 * has USER == 0, otherwise routes to local cache. When disabled, always
 * routes to local cache.
 */
static whKeyCacheContext* _GetCacheContext(whServerContext* server,
                                           whKeyId          keyId)
{
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    if (_IsGlobalKey(keyId)) {
        return &server->nvm->globalCache;
    }
#else
    (void)keyId;
#endif
    return &server->localCache;
}

/* Object operation types for policy checking */
typedef enum {
    WH_OBJ_OP_CACHE = 0,
    WH_OBJ_OP_COMMIT,
    WH_OBJ_OP_EVICT,
    WH_OBJ_OP_EXPORT,
    WH_OBJ_OP_REVOKE
} whObjOp;

static int _IsCommitted(whServerContext* server, whKeyId keyId)
{
    int ret;
    int big;
    int index;

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    ret = _FindInCache(server, keyId, &index, &big, NULL, NULL);
    if (ret != WH_ERROR_OK) {
        return 0;
    }

    if (big == 0) {
        return ctx->cache[index].committed;
    }
    else {
        return ctx->bigCache[index].committed;
    }
}

/* Centralized cache/NVM policy: enforce NONMODIFIABLE/NONEXPORTABLE at the
 * object layer. Usage enforcement remains separate. */
static int _ObjectCheckPolicy(whServerContext* server, whObjOp op,
                              whKeyId keyId)
{
    whNvmMetadata* cacheMeta = NULL;
    whNvmMetadata  nvmMeta;
    whNvmFlags     flags;
    int            ret;
    int            foundInCache = 0;
    int            foundInNvm   = 0;

    if ((server == NULL) || (WH_KEYID_ISERASED(keyId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    /* Check cache first */
    ret = _FindInCache(server, keyId, NULL, NULL, NULL, &cacheMeta);
    if (ret == WH_ERROR_OK && cacheMeta != NULL) {
        foundInCache = 1;
    }
    else if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* Check NVM if not in cache */
    if (!foundInCache) {
        ret = wh_Nvm_GetMetadata(server->nvm, keyId, &nvmMeta);
        if (ret == WH_ERROR_OK) {
            foundInNvm = 1;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            return ret;
        }
    }

    /* Object not found */
    if (!foundInCache && !foundInNvm) {
        return WH_ERROR_NOTFOUND;
    }

    /* Get flags from the appropriate source */
    flags = (foundInCache) ? cacheMeta->flags : nvmMeta.flags;

    switch (op) {
        case WH_OBJ_OP_CACHE:
            if (flags & WH_NVM_FLAGS_NONMODIFIABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_OBJ_OP_EVICT:
            if (_IsCommitted(server, keyId)) {
                /* Committed objects can always be evicted */
                break;
            }
            if (flags &
                (WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE)) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_OBJ_OP_EXPORT:
            if (flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_OBJ_OP_COMMIT:
        case WH_OBJ_OP_REVOKE:
            /* Always allowed */
            break;
        default:
            /* unknown operation */
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Find an object in the specified cache context
 */
static int _FindInKeyCache(whKeyCacheContext* ctx, whKeyId keyId,
                           int* out_index, int* out_big, uint8_t** out_buffer,
                           whNvmMetadata** out_meta)
{
    int            ret = WH_ERROR_NOTFOUND;
    int            i;
    int            index  = -1;
    int            big    = -1;
    whNvmMetadata* meta   = NULL;
    uint8_t*       buffer = NULL;

    /* Search regular cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (ctx->cache[i].meta->id == keyId) {
            big    = 0;
            index  = i;
            meta   = ctx->cache[i].meta;
            buffer = ctx->cache[i].buffer;
            break;
        }
    }

    /* Search big cache if not found */
    if (index == -1) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == keyId) {
                big    = 1;
                index  = i;
                meta   = ctx->bigCache[i].meta;
                buffer = ctx->bigCache[i].buffer;
                break;
            }
        }
    }

    /* Set output parameters if found */
    if (index != -1) {
        if (out_index != NULL)
            *out_index = index;
        if (out_big != NULL)
            *out_big = big;
        if (out_meta != NULL)
            *out_meta = meta;
        if (out_buffer != NULL)
            *out_buffer = buffer;
        ret = WH_ERROR_OK;
    }

    return ret;
}

static int _EvictSlot(uint8_t* buf, whNvmMetadata* meta)
{
    uint16_t len = meta->len;
    memset(meta, 0, sizeof(*meta));
    meta->id = WH_KEYID_ERASED;
    memset(buf, 0, len);
    return WH_ERROR_OK;
}

/**
 * @brief Get an available cache slot from the specified cache context
 */
static int _GetKeyCacheSlot(whKeyCacheContext* ctx, uint16_t keySz,
                            uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int            foundIndex = -1;
    int            i;
    int            evictRet = WH_ERROR_OK;
    uint8_t*       slotBuf  = NULL;
    whNvmMetadata* slotMeta = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Determine which cache to use based on object size */
    if (keySz <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* Search regular cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed object to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (ctx->cache[i].committed == 1) {
                    evictRet =
                        _EvictSlot(ctx->cache[i].buffer, ctx->cache[i].meta);
                    if (evictRet == WH_ERROR_OK) {
                        foundIndex = i;
                        break;
                    }
                }
            }
        }

        /* Zero slot and capture pointers */
        if (foundIndex >= 0) {
            memset(&ctx->cache[foundIndex], 0, sizeof(whCacheSlot));
            slotBuf  = ctx->cache[foundIndex].buffer;
            slotMeta = ctx->cache[foundIndex].meta;
        }
    }
    else {
        /* Search big cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed object to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (ctx->bigCache[i].committed == 1) {
                    evictRet = _EvictSlot(ctx->bigCache[i].buffer,
                                          ctx->bigCache[i].meta);
                    if (evictRet == WH_ERROR_OK) {
                        foundIndex = i;
                        break;
                    }
                }
            }
        }

        /* Zero slot and capture pointers */
        if (foundIndex >= 0) {
            memset(&ctx->bigCache[foundIndex], 0, sizeof(whBigCacheSlot));
            slotBuf  = ctx->bigCache[foundIndex].buffer;
            slotMeta = ctx->bigCache[foundIndex].meta;
        }
    }

    if (foundIndex == -1) {
        return WH_ERROR_NOSPACE;
    }

    /* Copy out pointers only if caller provided non-NULL output parameters */
    if (outBuf != NULL) {
        *outBuf = slotBuf;
    }
    if (outMeta != NULL) {
        *outMeta = slotMeta;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Evict an object from the specified cache context
 * zeroes the buffer
 */
static int _EvictFromCache(whKeyCacheContext* ctx, whKeyId keyId)
{
    whNvmMetadata* meta      = NULL;
    uint8_t*       outBuffer = NULL;

    int ret = _FindInKeyCache(ctx, keyId, NULL, NULL, &outBuffer, &meta);

    if (ret == WH_ERROR_OK && meta != NULL) {
        return _EvictSlot(outBuffer, meta);
    }

    return ret;
}

/**
 * @brief Mark a cached object as committed
 */
static int _MarkCommitted(whKeyCacheContext* ctx, whKeyId keyId, int committed)
{
    int index = -1;
    int big   = -1;
    int ret   = _FindInKeyCache(ctx, keyId, &index, &big, NULL, NULL);

    if (ret == WH_ERROR_OK) {
        if (big == 0) {
            ctx->cache[index].committed = committed;
        }
        else {
            ctx->bigCache[index].committed = committed;
        }
    }

    return ret;
}

static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta)
{
    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    return _FindInKeyCache(ctx, keyId, out_index, out_big, out_buffer,
                           out_meta);
}

static void _revokeObject(whNvmMetadata* meta)
{
    /* Set NONMODIFIABLE flag and clear all usage flags */
    meta->flags |= WH_NVM_FLAGS_NONMODIFIABLE;
    meta->flags &= ~WH_NVM_FLAGS_USAGE_ANY;
}

static int _isObjectRevoked(whNvmMetadata* meta)
{
    if ((meta->flags & WH_NVM_FLAGS_NONMODIFIABLE) &&
        ((meta->flags & WH_NVM_FLAGS_USAGE_ANY) == 0)) {
        return 1;
    }

    return 0;
}

/*
 * Public functions
 */

int wh_Server_ObjectGetUniqueId(whServerContext* server, whNvmId* inout_id)
{
    int     ret   = WH_ERROR_OK;
    int     found = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whKeyId key_id = *inout_id;
    int     type   = WH_KEYID_TYPE(key_id);
    int     user   = WH_KEYID_USER(key_id);
    whNvmId buildId;

    whKeyCacheContext* ctx = _GetCacheContext(server, key_id);

    /* try every index until we find a unique one, don't worry about capacity */
    for (id = WH_KEYID_IDMAX; id > WH_KEYID_ERASED; id--) {
        /* id loop var is not an input client ID so we don't need to handle the
         * global case */
        buildId = WH_MAKE_KEYID(type, user, id);

        /* Check against cache objects using unified cache functions */
        ret = _FindInKeyCache(ctx, buildId, NULL, NULL, NULL, NULL);
        if (ret == WH_ERROR_OK) {
            /* Found in cache, try next ID */
            continue;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            return ret;
        }

        /* Check if objId exists in NVM */
        ret = wh_Nvm_GetMetadata(server->nvm, buildId, NULL);
        if (ret == WH_ERROR_NOTFOUND) {
            /* object doesn't exist in NVM, we found a candidate ID */
            found = 1;
            break;
        }

        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    if (!found) {
        return WH_ERROR_NOSPACE;
    }

    /* Return found id */
    *inout_id = buildId;
    return WH_ERROR_OK;
}

/* find a slot to cache an object. If object is already there, evict first */
int wh_Server_ObjectGetCacheSlot(whServerContext* server, whKeyId objId,
                                 uint16_t objSz, uint8_t** outBuf,
                                 whNvmMetadata** outMeta)
{
    whKeyCacheContext* ctx;
    int                ret;
    int                idx       = -1;
    int                isBig     = -1;
    uint8_t*           buf       = NULL;
    whNvmMetadata*     foundMeta = NULL;

    if (server == NULL || (objSz > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE &&
                           objSz > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE)) {
        return WH_ERROR_BADARGS;
    }

    ret = _FindInCache(server, objId, &idx, &isBig, &buf, &foundMeta);
    if (ret == WH_ERROR_OK) {
        /* Object is already cached; evict it first */
        ret = wh_Server_ObjectCacheEvict(server, objId);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }
    else if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    ctx = _GetCacheContext(server, objId);
    return _GetKeyCacheSlot(ctx, objSz, outBuf, outMeta);
}

int wh_Server_ObjectGetCacheSlotChecked(whServerContext* server, whKeyId objId,
                                        uint16_t objSz, uint8_t** outBuf,
                                        whNvmMetadata** outMeta)
{
    int ret;
    ret = _ObjectCheckPolicy(server, WH_OBJ_OP_CACHE, objId);
    if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }
    return wh_Server_ObjectGetCacheSlot(server, objId, objSz, outBuf, outMeta);
}

static int _ObjectCacheAdd(whServerContext* server, whNvmMetadata* meta,
                           uint8_t* in, int checked)
{
    uint8_t*       slotBuf;
    whNvmMetadata* slotMeta;
    int            ret;

    /* make sure id is valid */
    if ((server == NULL) || (meta == NULL) || (in == NULL) ||
        (WH_KEYID_ISERASED(meta->id)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
         && (WH_KEYID_TYPE(meta->id) != WH_KEYTYPE_SHE)
#endif
             ) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    if (checked) {
        ret = wh_Server_ObjectGetCacheSlotChecked(server, meta->id, meta->len,
                                                  &slotBuf, &slotMeta);
    }
    else {
        ret = wh_Server_ObjectGetCacheSlot(server, meta->id, meta->len,
                                           &slotBuf, &slotMeta);
    }
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    memcpy(slotBuf, in, meta->len);
    memcpy((uint8_t*)slotMeta, (uint8_t*)meta, sizeof(whNvmMetadata));
    _MarkCommitted(_GetCacheContext(server, meta->id), meta->id, 0);

    WH_DEBUG_SERVER_VERBOSE("hsmObjectCache: cached objid=0x%X, len=%u\n",
                            meta->id, meta->len);
    WH_DEBUG_VERBOSE_HEXDUMP("[server] objectCache: data=", in, meta->len);

    return WH_ERROR_OK;
}

int wh_Server_ObjectCacheAdd(whServerContext* server, whNvmMetadata* meta,
                             uint8_t* in)
{
    return _ObjectCacheAdd(server, meta, in, 0);
}

int wh_Server_ObjectCacheAddChecked(whServerContext* server,
                                    whNvmMetadata* meta, uint8_t* in)
{
    return _ObjectCacheAdd(server, meta, in, 1);
}

/* try to put the specified object into cache if it isn't already, return
 * pointers to meta and the cached data */
int wh_Server_ObjectCacheLoad(whServerContext* server, whKeyId objId,
                              uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int             ret            = 0;
    int             foundIndex     = -1;
    int             foundBigIndex  = -1;
    uint8_t*        cacheBufLocal  = NULL;
    whNvmMetadata*  cacheMetaLocal = NULL;
    uint8_t**       cacheBufOut;
    whNvmMetadata** cacheMetaOut;
    whNvmMetadata   tmpMeta[1];

    if ((server == NULL) || (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    /* Use local buffers to allow for optional (NULL) output parameters */
    cacheBufOut  = (outBuf != NULL) ? outBuf : (uint8_t**)&cacheBufLocal;
    cacheMetaOut = (outMeta != NULL) ? outMeta : &cacheMetaLocal;

    ret = _FindInCache(server, objId, &foundIndex, &foundBigIndex, cacheBufOut,
                       cacheMetaOut);
    if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* object not in the cache */

    /* Not in cache. Check if it is in NVM */
    ret = wh_Nvm_GetMetadata(server->nvm, objId, tmpMeta);
    if (ret == WH_ERROR_OK) {
        /* Object found in NVM, get a free cache slot */
        ret = wh_Server_ObjectGetCacheSlot(server, objId, tmpMeta->len,
                                           cacheBufOut, cacheMetaOut);
        if (ret == WH_ERROR_OK) {
            /* Read the object from NVM into the cache slot */
            ret =
                wh_Nvm_Read(server->nvm, objId, 0, tmpMeta->len, *cacheBufOut);
            if (ret == WH_ERROR_OK) {
                /* Copy the metadata to the cache slot if read is
                 * successful */
                memcpy((uint8_t*)*cacheMetaOut, (uint8_t*)tmpMeta,
                       sizeof(whNvmMetadata));
                _MarkCommitted(_GetCacheContext(server, objId), objId, 1);
            }
        }
    }

    return ret;
}

/* Reads object from cache or NVM */
int wh_Server_ObjectCacheExport(whServerContext* server, whKeyId objId,
                                whNvmMetadata* outMeta, uint8_t* out,
                                uint32_t* outSz)
{
    int            ret = 0;
    whNvmMetadata  meta[1];
    whNvmMetadata* cacheMeta   = NULL;
    uint8_t*       cacheBuffer = NULL;

    if ((server == NULL) || (outSz == NULL) ||
        (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
         && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
             )) {
        return WH_ERROR_BADARGS;
    }

    /* Check the cache using unified function */
    ret = _FindInCache(server, objId, NULL, NULL, &cacheBuffer, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        /* Found in cache */
        if (cacheMeta->len > *outSz)
            return WH_ERROR_NOSPACE;
        if (outMeta != NULL) {
            memcpy((uint8_t*)outMeta, (uint8_t*)cacheMeta,
                   sizeof(whNvmMetadata));
        }
        if (out != NULL) {
            memcpy(out, cacheBuffer, cacheMeta->len);
        }
        *outSz = cacheMeta->len;
        return 0;
    }

    /* Not in cache, try to read the metadata from NVM */
    ret = wh_Nvm_GetMetadata(server->nvm, objId, meta);
    if (ret == 0) {
        /* Check buffer capacity before reading (matching cache path) */
        if (meta->len > *outSz)
            return WH_ERROR_NOSPACE;
        /* set outSz */
        *outSz = meta->len;
        /* read meta */
        if (outMeta != NULL)
            memcpy((uint8_t*)outMeta, (uint8_t*)meta, sizeof(*outMeta));
        /* read the object */
        if (out != NULL)
            ret = wh_Nvm_Read(server->nvm, objId, 0, *outSz, out);
    }
    /* cache object if free slot, will only kick out other committed objects */
    if (ret == 0 && out != NULL) {
        (void)wh_Server_ObjectCacheAdd(server, meta, out);
    }

#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* use empty key of zeros if we couldn't find the master ecu key */
    if ((ret == WH_ERROR_NOTFOUND) &&
        (WH_KEYID_TYPE(objId) == WH_KEYTYPE_SHE) &&
        (WH_KEYID_ID(objId) == WH_SHE_MASTER_ECU_KEY_ID)) {
        if (out != NULL)
            memset(out, 0, WH_SHE_KEY_SZ);
        *outSz = WH_SHE_KEY_SZ;
        if (outMeta != NULL) {
            memset(outMeta, 0, sizeof(*outMeta));
            outMeta->len = WH_SHE_KEY_SZ;
            outMeta->id  = objId;
        }
        ret = 0;
    }
#endif

    return ret;
}

int wh_Server_ObjectCacheExportChecked(whServerContext* server, whKeyId objId,
                                       whNvmMetadata* outMeta, uint8_t* out,
                                       uint32_t* outSz)
{
    int ret;

    ret = _ObjectCheckPolicy(server, WH_OBJ_OP_EXPORT, objId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_ObjectCacheExport(server, objId, outMeta, out, outSz);
}

int wh_Server_ObjectCacheEvict(whServerContext* server, whNvmId objId)
{
    int                ret = 0;
    whKeyCacheContext* ctx;

    if ((server == NULL) || (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    /* Get the appropriate cache context for this object */
    ctx = _GetCacheContext(server, objId);

    /* Use the unified evict function */
    ret = _EvictFromCache(ctx, objId);

    if (ret == 0) {
        WH_DEBUG_SERVER_VERBOSE(
            "wh_Server_ObjectCacheEvict: evicted objid=0x%X\n", objId);
    }

    return ret;
}

int wh_Server_ObjectCacheEvictChecked(whServerContext* server, whNvmId objId)
{
    int ret;

    ret = _ObjectCheckPolicy(server, WH_OBJ_OP_EVICT, objId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_ObjectCacheEvict(server, objId);
}

int wh_Server_ObjectCacheCommit(whServerContext* server, whNvmId objId)
{
    uint8_t*           slotBuf;
    whNvmMetadata*     slotMeta;
    whNvmSize          size;
    int                ret;
    whKeyCacheContext* ctx;

    if ((server == NULL) || (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    /* Get the appropriate cache context for this object */
    ctx = _GetCacheContext(server, objId);

    /* Find the object and check NONPERSISTABLE flag */
    ret = _FindInKeyCache(ctx, objId, NULL, NULL, &slotBuf, &slotMeta);
    if (ret == WH_ERROR_OK && (slotMeta->flags & WH_NVM_FLAGS_NONPERSISTABLE)) {
        return WH_ERROR_ACCESS;
    }
    if (ret == WH_ERROR_OK) {
        size = slotMeta->len;
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, slotMeta, size, slotBuf);
        if (ret == 0) {
            /* Mark object as committed using unified function */
            (void)_MarkCommitted(ctx, objId, 1);
        }
    }
    return ret;
}

int wh_Server_ObjectCacheCommitChecked(whServerContext* server, whNvmId objId)
{
    int ret;

    ret = _ObjectCheckPolicy(server, WH_OBJ_OP_COMMIT, objId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_ObjectCacheCommit(server, objId);
}

int wh_Server_ObjectCacheErase(whServerContext* server, whNvmId objId)
{
    if ((server == NULL) || (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    /* remove the object from the cache if present */
    (void)wh_Server_ObjectCacheEvict(server, objId);

    /* destroy the object */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &objId);
}

int wh_Server_ObjectCacheEraseChecked(whServerContext* server, whNvmId objId)
{
    if ((server == NULL) || (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    /* remove the object from the cache if present */
    (void)wh_Server_ObjectCacheEvictChecked(server, objId);

    /* destroy the object */
    return wh_Nvm_DestroyObjectsChecked(server->nvm, 1, &objId);
}

int wh_Server_ObjectCacheRevoke(whServerContext* server, whKeyId objId)
{
    int            ret;
    int            isInNvm   = 0;
    uint8_t*       cacheBuf  = NULL;
    whNvmMetadata* cacheMeta = NULL;

    if ((server == NULL) || (WH_KEYID_ISERASED(objId)
#ifdef WOLFHSM_CFG_SHE_EXTENSION
                            && (WH_KEYID_TYPE(objId) != WH_KEYTYPE_SHE)
#endif
                                )) {
        return WH_ERROR_BADARGS;
    }

    ret = _ObjectCheckPolicy(server, WH_OBJ_OP_REVOKE, objId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Nvm_GetMetadata(server->nvm, objId, NULL);
    if (ret == WH_ERROR_OK) {
        isInNvm = 1;
    }
    else if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* be sure to have the object in the cache */
    ret = wh_Server_ObjectCacheLoad(server, objId, &cacheBuf, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* if already revoked and committed, nothing to do */
    if (_isObjectRevoked(cacheMeta) && _IsCommitted(server, objId)) {
        return WH_ERROR_OK;
    }

    /* Revoke the object by updating its metadata */
    _revokeObject(cacheMeta);
    /* commit the changes */
    if (isInNvm) {
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, cacheMeta,
                                          cacheMeta->len, cacheBuf);
        if (ret == WH_ERROR_OK) {
            _MarkCommitted(_GetCacheContext(server, objId), objId, 1);
        }
    }

    return ret;
}

int wh_Server_ObjectEnforceUsage(const whNvmMetadata* meta,
                                 whNvmFlags           requiredUsage)
{
    whNvmFlags actualFlags;

    /* Validate input parameters */
    if (meta == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* We only care about the usage flags */
    requiredUsage &= WH_NVM_FLAGS_USAGE_ANY;

    /* Check if the object has ALL the required usage flags set */
    actualFlags = meta->flags & WH_NVM_FLAGS_USAGE_ANY;
    if ((actualFlags & requiredUsage) == requiredUsage) {
        return WH_ERROR_OK;
    }

    /* Object does not have ALL the required usage flags */
    return WH_ERROR_USAGE;
}

int wh_Server_ObjectFindEnforceUsage(whServerContext* server, whKeyId objId,
                                     whNvmFlags requiredUsage)
{
    int            ret;
    whNvmMetadata* meta = NULL;

    /* Validate input parameters */
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Load the object to obtain the metadata */
    ret = wh_Server_ObjectCacheLoad(server, objId, NULL, &meta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Enforce the usage policy with the obtained metadata */
    return wh_Server_ObjectEnforceUsage(meta, requiredUsage);
}

#ifdef WOLFHSM_CFG_DMA

static int _ObjectCacheAddDma(whServerContext* server, whNvmMetadata* meta,
                              uint64_t objAddr, int checked)
{
    int              ret;
    uint8_t*         buffer;
    whNvmMetadata*   slotMeta;
    whServerDmaFlags dmaFlags;

    memset(&dmaFlags, 0, sizeof(dmaFlags));

    /* Get a cache slot */
    if (checked) {
        ret = wh_Server_ObjectGetCacheSlotChecked(server, meta->id, meta->len,
                                                  &buffer, &slotMeta);
    }
    else {
        ret = wh_Server_ObjectGetCacheSlot(server, meta->id, meta->len, &buffer,
                                           &slotMeta);
    }
    if (ret != 0) {
        return ret;
    }

    /* Copy metadata */
    memcpy(slotMeta, meta, sizeof(whNvmMetadata));

    /* Copy object data using DMA */
    ret = whServerDma_CopyFromClient(server, buffer, (uintptr_t)objAddr,
                                     meta->len, dmaFlags);
    if (ret != 0) {
        /* Clear the slot on error */
        memset(buffer, 0, meta->len);
        slotMeta->id = WH_KEYID_ERASED;
    }
    else {
        _MarkCommitted(_GetCacheContext(server, meta->id), meta->id, 0);
    }

    return ret;
}

int wh_Server_ObjectCacheAddDma(whServerContext* server, whNvmMetadata* meta,
                                uint64_t objAddr)
{
    return _ObjectCacheAddDma(server, meta, objAddr, 0);
}

int wh_Server_ObjectCacheAddDmaChecked(whServerContext* server,
                                       whNvmMetadata* meta, uint64_t objAddr)
{
    return _ObjectCacheAddDma(server, meta, objAddr, 1);
}

int wh_Server_ObjectCacheExportDma(whServerContext* server, whKeyId objId,
                                   uint64_t objAddr, uint64_t objSz,
                                   whNvmMetadata* outMeta)
{
    int              ret;
    uint8_t*         buffer;
    whNvmMetadata*   cacheMeta;
    whServerDmaFlags dmaFlags;

    memset(&dmaFlags, 0, sizeof(dmaFlags));

    /* bring object into cache */
    ret = wh_Server_ObjectCacheLoad(server, objId, &buffer, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (objSz < cacheMeta->len) {
        return WH_ERROR_NOSPACE;
    }

    memcpy(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy object data using DMA */
    ret = whServerDma_CopyToClient(server, (uintptr_t)objAddr, buffer,
                                   outMeta->len, dmaFlags);

    return ret;
}

int wh_Server_ObjectCacheExportDmaChecked(whServerContext* server,
                                          whKeyId objId, uint64_t objAddr,
                                          uint64_t       objSz,
                                          whNvmMetadata* outMeta)
{
    int ret;

    ret = _ObjectCheckPolicy(server, WH_OBJ_OP_EXPORT, objId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_ObjectCacheExportDma(server, objId, objAddr, objSz,
                                          outMeta);
}

#endif /* WOLFHSM_CFG_DMA */

#ifdef WOLFHSM_CFG_KEYWRAP
#ifndef NO_AES
#ifdef HAVE_AESGCM

static int _AesGcmObjectWrap(whServerContext* server, whKeyId serverKeyId,
                             uint8_t* keyIn, uint16_t keySz,
                             whNvmMetadata* metadataIn, uint8_t* wrappedKeyOut,
                             uint16_t wrappedKeySz)
{
    int            ret = 0;
    Aes            aes[1];
    uint8_t        authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t        iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t*       serverKey;
    uint32_t       serverKeySz;
    whNvmMetadata* serverKeyMetadata;
    uint8_t  plainBlob[sizeof(*metadataIn) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    uint32_t plainBlobSz = sizeof(*metadataIn) + keySz;
    uint8_t* encBlob;

    if (server == NULL || keyIn == NULL || metadataIn == NULL ||
        wrappedKeyOut == NULL || plainBlobSz > sizeof(plainBlob)) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the buffer is big enough to hold the wrapped key */
    if (wrappedKeySz <
        sizeof(iv) + sizeof(authTag) + sizeof(*metadataIn) + keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Get the server side key */
    ret = wh_Server_ObjectCacheLoad(server, serverKeyId, &serverKey,
                                    &serverKeyMetadata);
    if (ret != WH_ERROR_OK) {
        goto wrap_cleanup;
    }
    serverKeySz = serverKeyMetadata->len;

    /* Validate key usage policy for wrapping (KEK) */
    ret = wh_Server_ObjectEnforceUsage(serverKeyMetadata,
                                       WH_NVM_FLAGS_USAGE_WRAP);
    if (ret != WH_ERROR_OK) {
        goto wrap_cleanup;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->devId);
    if (ret != 0) {
        goto wrap_cleanup;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        goto wrap_cleanup;
    }

    /* Generate the IV */
    ret = wc_RNG_GenerateBlock(server->crypto->rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_AesFree(aes);
        goto wrap_cleanup;
    }

    /* Combine key and metadata into one blob */
    memcpy(plainBlob, metadataIn, sizeof(*metadataIn));
    memcpy(plainBlob + sizeof(*metadataIn), keyIn, keySz);

    /* Place the encrypted blob after the IV and Auth Tag */
    encBlob = (uint8_t*)wrappedKeyOut + sizeof(iv) + sizeof(authTag);

    /* Encrypt the blob */
    ret = wc_AesGcmEncrypt(aes, encBlob, plainBlob, plainBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        goto wrap_cleanup;
    }

    /* Prepend IV + authTag to encrypted blob */
    memcpy(wrappedKeyOut, iv, sizeof(iv));
    memcpy(wrappedKeyOut + sizeof(iv), authTag, sizeof(authTag));

    wc_AesFree(aes);

wrap_cleanup:
    wc_ForceZero(plainBlob, sizeof(plainBlob));
    wc_ForceZero(iv, sizeof(iv));
    wc_ForceZero(authTag, sizeof(authTag));

    return ret;
}

static int _AesGcmObjectUnwrap(whServerContext* server, uint16_t serverKeyId,
                               void* wrappedKeyIn, uint16_t wrappedKeySz,
                               whNvmMetadata* metadataOut, void* keyOut,
                               uint16_t keySz)
{
    int            ret = 0;
    Aes            aes[1];
    uint8_t        authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t        iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t*       serverKey;
    uint32_t       serverKeySz;
    whNvmMetadata* serverKeyMetadata;
    uint8_t*       encBlob;
    uint16_t       encBlobSz;
    uint8_t plainBlob[sizeof(*metadataOut) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];

    if (server == NULL || wrappedKeyIn == NULL || metadataOut == NULL ||
        keyOut == NULL || keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (wrappedKeySz < sizeof(iv) + sizeof(authTag)) {
        return WH_ERROR_BADARGS;
    }

    encBlob   = (uint8_t*)wrappedKeyIn + sizeof(iv) + sizeof(authTag);
    encBlobSz = wrappedKeySz - sizeof(iv) - sizeof(authTag);

    /* Get the server side key */
    ret = wh_Server_ObjectCacheLoad(server, serverKeyId, &serverKey,
                                    &serverKeyMetadata);
    if (ret != WH_ERROR_OK) {
        goto unwrap_cleanup;
    }
    serverKeySz = serverKeyMetadata->len;

    /* Validate key usage policy for unwrapping (KEK) */
    ret = wh_Server_ObjectEnforceUsage(serverKeyMetadata,
                                       WH_NVM_FLAGS_USAGE_WRAP);
    if (ret != WH_ERROR_OK) {
        goto unwrap_cleanup;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->devId);
    if (ret != 0) {
        goto unwrap_cleanup;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        goto unwrap_cleanup;
    }

    /* Extract IV and authTag from wrappedKeyIn */
    memcpy(iv, wrappedKeyIn, sizeof(iv));
    memcpy(authTag, (uint8_t*)wrappedKeyIn + sizeof(iv), sizeof(authTag));

    /* Decrypt the encrypted blob */
    ret = wc_AesGcmDecrypt(aes, plainBlob, encBlob, encBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        goto unwrap_cleanup;
    }

    /* Extract metadata and key from the decrypted blob */
    memcpy(metadataOut, plainBlob, sizeof(*metadataOut));
    memcpy(keyOut, plainBlob + sizeof(*metadataOut), keySz);

    wc_AesFree(aes);

unwrap_cleanup:
    wc_ForceZero(plainBlob, sizeof(plainBlob));
    wc_ForceZero(iv, sizeof(iv));
    wc_ForceZero(authTag, sizeof(authTag));

    return ret;
}

#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
#endif /* WOLFHSM_CFG_KEYWRAP */

/*
 * Request Handler
 */

int wh_Server_HandleObjectRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet)
{
    int           ret = WH_ERROR_OK;
    uint8_t*      in;
    uint8_t*      out;
    whNvmMetadata meta[1] = {{0}};

    (void)seq;

    if ((server == NULL) || (req_packet == NULL) || (out_resp_size == NULL) ||
        (resp_packet == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_OBJECT_CACHE_ADD: {
            whMessageObject_CacheAddRequest  req;
            whMessageObject_CacheAddResponse resp;
            uint16_t                         availableSz;

            memset(&resp, 0, sizeof(resp));

            /* Validate request packet is at least as large as fixed header */
            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateCacheAddResponse(
                    magic, &resp,
                    (whMessageObject_CacheAddResponse*)resp_packet);
                break;
            }

            /* translate request */
            (void)wh_MessageObject_TranslateCacheAddRequest(
                magic, (whMessageObject_CacheAddRequest*)req_packet, &req);

            /* in is after fixed size fields */
            in = (uint8_t*)req_packet + sizeof(req);

            /* Validate client-controlled size against actual packet size */
            availableSz = req_size - sizeof(req);
            if (req.sz > availableSz) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateCacheAddResponse(
                    magic, &resp,
                    (whMessageObject_CacheAddResponse*)resp_packet);
                break;
            }

            /* set the metadata fields */
            meta->id = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);
            meta->access = req.access;
            meta->flags  = req.flags;
            meta->len    = (uint16_t)req.sz;
            /* truncate label if it's too large */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                req.labelSz = WH_NVM_LABEL_LEN;
            }
            memcpy(meta->label, req.label, req.labelSz);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* get a new id if one wasn't provided */
                if (WH_KEYID_ISERASED(meta->id)) {
                    ret = wh_Server_ObjectGetUniqueId(server, &meta->id);
                }
                /* cache the object */
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_ObjectCacheAddChecked(server, meta, in);
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */

            if (ret == WH_ERROR_OK) {
                /* Translate server keyId back to client format with flags */
                resp.id = wh_KeyId_TranslateToClient(meta->id);
            }
            resp.rc = ret;

            (void)wh_MessageObject_TranslateCacheAddResponse(
                magic, &resp, (whMessageObject_CacheAddResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_CACHE_LOAD: {
            whMessageObject_TypeIdRequest  req;
            whMessageObject_SimpleResponse resp;
            whKeyId                        keyId;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateSimpleResponse(
                    magic, &resp,
                    (whMessageObject_SimpleResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateTypeIdRequest(
                magic, (whMessageObject_TypeIdRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_ObjectCacheLoad(server, keyId, NULL, NULL);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateSimpleResponse(
                magic, &resp, (whMessageObject_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_CACHE_EVICT: {
            whMessageObject_TypeIdRequest  req;
            whMessageObject_SimpleResponse resp;
            whKeyId                        keyId;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateSimpleResponse(
                    magic, &resp,
                    (whMessageObject_SimpleResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateTypeIdRequest(
                magic, (whMessageObject_TypeIdRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_ObjectCacheEvictChecked(server, keyId);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateSimpleResponse(
                magic, &resp, (whMessageObject_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_CACHE_COMMIT: {
            whMessageObject_TypeIdRequest  req;
            whMessageObject_SimpleResponse resp;
            whKeyId                        keyId;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateSimpleResponse(
                    magic, &resp,
                    (whMessageObject_SimpleResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateTypeIdRequest(
                magic, (whMessageObject_TypeIdRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_ObjectCacheCommitChecked(server, keyId);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateSimpleResponse(
                magic, &resp, (whMessageObject_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_CACHE_EXPORT: {
            whMessageObject_TypeIdRequest       req;
            whMessageObject_CacheExportResponse resp;
            whKeyId                             keyId;
            uint32_t                            keySz;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateCacheExportResponse(
                    magic, &resp,
                    (whMessageObject_CacheExportResponse*)resp_packet);
                break;
            }

            /* translate request */
            (void)wh_MessageObject_TranslateTypeIdRequest(
                magic, (whMessageObject_TypeIdRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            /* out is after fixed size fields */
            out   = (uint8_t*)resp_packet + sizeof(resp);
            keySz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp);

            resp.len = 0;
            ret      = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* read the object */
                ret = wh_Server_ObjectCacheExportChecked(server, keyId, meta,
                                                         out, &keySz);

                /* Only provide output if no error */
                if (ret == WH_ERROR_OK) {
                    resp.len = keySz;
                    memcpy(resp.label, meta->label, sizeof(meta->label));
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateCacheExportResponse(
                magic, &resp,
                (whMessageObject_CacheExportResponse*)resp_packet);

            *out_resp_size = sizeof(resp) + resp.len;
        } break;

        case WH_OBJECT_CACHE_REVOKE: {
            whMessageObject_TypeIdRequest  req;
            whMessageObject_SimpleResponse resp;
            whKeyId                        keyId;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateSimpleResponse(
                    magic, &resp,
                    (whMessageObject_SimpleResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateTypeIdRequest(
                magic, (whMessageObject_TypeIdRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_ObjectCacheRevoke(server, keyId);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateSimpleResponse(
                magic, &resp, (whMessageObject_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_NVM_ADD: {
            whMessageObject_NvmAddRequest  req;
            whMessageObject_SimpleResponse resp;
            whNvmSize                      dataSz;

            memset(&resp, 0, sizeof(resp));

            /* Validate packet size against fixed header */
            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateSimpleResponse(
                    magic, &resp,
                    (whMessageObject_SimpleResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateNvmAddRequest(
                magic, (whMessageObject_NvmAddRequest*)req_packet, &req);

            /* in is after fixed size fields */
            in = (uint8_t*)req_packet + sizeof(req);

            /* set the metadata fields */
            meta->id = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);
            meta->access = req.access;
            meta->flags  = req.flags;
            /* truncate label if it's too large */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                req.labelSz = WH_NVM_LABEL_LEN;
            }
            memcpy(meta->label, req.label, req.labelSz);

            /* remaining bytes are data */
            dataSz    = req_size - sizeof(req);
            meta->len = dataSz;

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Nvm_AddObjectChecked(server->nvm, meta, dataSz, in);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateSimpleResponse(
                magic, &resp, (whMessageObject_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_NVM_DESTROY: {
            whMessageObject_TypeIdRequest  req;
            whMessageObject_SimpleResponse resp;
            whKeyId                        keyId;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateSimpleResponse(
                    magic, &resp,
                    (whMessageObject_SimpleResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateTypeIdRequest(
                magic, (whMessageObject_TypeIdRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Nvm_DestroyObjectsChecked(server->nvm, 1, &keyId);

                /* Evict the destroyed object from cache if present */
                if (ret == WH_ERROR_OK) {
                    (void)wh_Server_ObjectCacheEvict(server, keyId);
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateSimpleResponse(
                magic, &resp, (whMessageObject_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_NVM_READ: {
            whMessageObject_NvmReadRequest  req;
            whMessageObject_NvmReadResponse resp;
            whKeyId                         keyId;
            uint16_t                        data_len;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateNvmReadResponse(
                    magic, &resp,
                    (whMessageObject_NvmReadResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateNvmReadRequest(
                magic, (whMessageObject_NvmReadRequest*)req_packet, &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            /* out is after fixed size fields */
            out      = (uint8_t*)resp_packet + sizeof(resp);
            data_len = req.data_len;

            /* Clamp to available response buffer space */
            if (data_len > WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp)) {
                data_len = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp);
            }

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Nvm_ReadChecked(server->nvm, keyId, req.offset,
                                         data_len, out);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateNvmReadResponse(
                magic, &resp, (whMessageObject_NvmReadResponse*)resp_packet);

            if (ret == WH_ERROR_OK) {
                *out_resp_size = sizeof(resp) + data_len;
            }
            else {
                *out_resp_size = sizeof(resp);
            }
        } break;

        case WH_OBJECT_NVM_GETAVAIL: {
            whMessageObject_NvmGetAvailResponse resp;

            memset(&resp, 0, sizeof(resp));
            /* TODO: implement NVM available space query */
            resp.rc            = WH_ERROR_NOTIMPL;
            resp.avail_size    = 0;
            resp.avail_objects = 0;

            (void)wh_MessageObject_TranslateNvmGetAvailResponse(
                magic, &resp,
                (whMessageObject_NvmGetAvailResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_NVM_ITERATE: {
            whMessageObject_NvmIterateResponse resp;

            memset(&resp, 0, sizeof(resp));
            /* TODO: implement NVM iteration */
            resp.rc    = WH_ERROR_NOTIMPL;
            resp.count = 0;
            resp.id    = 0;

            (void)wh_MessageObject_TranslateNvmIterateResponse(
                magic, &resp, (whMessageObject_NvmIterateResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

#ifdef WOLFHSM_CFG_KEYWRAP
        case WH_OBJECT_WRAP: {
            whMessageObject_WrapRequest  req;
            whMessageObject_WrapResponse resp;
            uint8_t*                     keyData;
            uint8_t*                     wrappedOut;
            whKeyId                      kekId;
            whNvmMetadata                wrapMeta;
            uint16_t                     capSz;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateWrapResponse(
                    magic, &resp,
                    (whMessageObject_WrapResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateWrapRequest(
                magic, (whMessageObject_WrapRequest*)req_packet, &req);

            keyData    = (uint8_t*)req_packet + sizeof(req);
            wrappedOut = (uint8_t*)resp_packet + sizeof(resp);

            /* KEK is always a crypto object regardless of wrapped object type
             */
            kekId = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.serverKekId);

            /* Validate client-controlled keySz against actual packet size */
            {
                uint16_t availableSz = req_size - sizeof(req);
                if (req.keySz > availableSz) {
                    resp.rc        = WH_ERROR_BADARGS;
                    *out_resp_size = sizeof(resp);
                    (void)wh_MessageObject_TranslateWrapResponse(
                        magic, &resp,
                        (whMessageObject_WrapResponse*)resp_packet);
                    break;
                }
            }

            /* Build metadata from request fields. Embed the wrapping
             * client's identity in the metadata ID for ownership validation
             * during unwrap. Use the KEK's translated ID to determine if
             * this is a global or local wrap. */
            memset(&wrapMeta, 0, sizeof(wrapMeta));
            {
                uint16_t ownerUser = server->comm->client_id;
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
                if ((req.ownerId & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0) {
                    ownerUser = WH_KEYUSER_GLOBAL;
                }
#endif
                wrapMeta.id = WH_MAKE_KEYID(req.type, ownerUser, 0);
            }
            wrapMeta.access = req.access;
            wrapMeta.flags  = req.flags;
            wrapMeta.len    = req.keySz;
            capSz           = sizeof(wrapMeta.label);
            memcpy(wrapMeta.label, req.label, capSz);

            resp.wrappedSz = 0;

#ifndef NO_AES
#ifdef HAVE_AESGCM
            if (req.cipherType == WC_CIPHER_AES_GCM) {
                uint16_t wrappedBufSz =
                    WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp);
                /* Use uint32_t to prevent overflow on large req.keySz */
                uint32_t expectedSz = (uint32_t)WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                      sizeof(wrapMeta) + req.keySz;

                if (expectedSz > wrappedBufSz) {
                    resp.rc = WH_ERROR_BUFFER_SIZE;
                }
                else {
                    ret = WH_SERVER_NVM_LOCK(server);
                    if (ret == WH_ERROR_OK) {
                        ret = _AesGcmObjectWrap(server, kekId, keyData,
                                                req.keySz, &wrapMeta,
                                                wrappedOut,
                                                (uint16_t)expectedSz);
                        (void)WH_SERVER_NVM_UNLOCK(server);
                    }
                    resp.rc = ret;
                    if (ret == WH_ERROR_OK) {
                        resp.wrappedSz = (uint16_t)expectedSz;
                    }
                }
            }
            else
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
            {
                resp.rc = WH_ERROR_BADARGS;
            }

            (void)wh_MessageObject_TranslateWrapResponse(
                magic, &resp, (whMessageObject_WrapResponse*)resp_packet);
            *out_resp_size = sizeof(resp) + resp.wrappedSz;
        } break;

        case WH_OBJECT_UNWRAP_CACHE: {
            whMessageObject_UnwrapCacheRequest  req;
            whMessageObject_UnwrapCacheResponse resp;
            uint8_t*                            wrappedIn;
            whKeyId                             kekId;
            whNvmMetadata                       unwrapMeta;
            uint8_t  keyBuf[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
            uint16_t keySz;
            uint16_t wrappedUser = 0;

            memset(&resp, 0, sizeof(resp));
            resp.id = WH_KEYID_ERASED;

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateUnwrapCacheResponse(
                    magic, &resp,
                    (whMessageObject_UnwrapCacheResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateUnwrapCacheRequest(
                magic, (whMessageObject_UnwrapCacheRequest*)req_packet, &req);

            wrappedIn = (uint8_t*)req_packet + sizeof(req);

            /* KEK is always a crypto object regardless of wrapped object type
             */
            kekId = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.serverKekId);

            /* Validate client-controlled wrappedSz against actual packet size
             */
            {
                uint16_t availableSz = req_size - sizeof(req);
                if (req.wrappedSz > availableSz) {
                    resp.rc        = WH_ERROR_BADARGS;
                    *out_resp_size = sizeof(resp);
                    (void)wh_MessageObject_TranslateUnwrapCacheResponse(
                        magic, &resp,
                        (whMessageObject_UnwrapCacheResponse*)resp_packet);
                    break;
                }
            }

#ifndef NO_AES
#ifdef HAVE_AESGCM
            if (req.cipherType == WC_CIPHER_AES_GCM) {
                if (req.wrappedSz <
                    WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(unwrapMeta)) {
                    resp.rc = WH_ERROR_BADARGS;
                }
                else {
                    keySz = req.wrappedSz - WH_KEYWRAP_AES_GCM_HEADER_SIZE -
                            sizeof(unwrapMeta);

                    ret = WH_SERVER_NVM_LOCK(server);
                    if (ret == WH_ERROR_OK) {
                        ret = _AesGcmObjectUnwrap(server, kekId, wrappedIn,
                                                  req.wrappedSz, &unwrapMeta,
                                                  keyBuf, keySz);
                        /* Validate decrypted metadata length matches
                         * expected key size derived from packet structure */
                        if (ret == WH_ERROR_OK &&
                            unwrapMeta.len != keySz) {
                            ret = WH_ERROR_BADARGS;
                        }
                        /* Validate ownership */
                        if (ret == WH_ERROR_OK) {
                            wrappedUser = WH_KEYID_USER(unwrapMeta.id);
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
                            if (wrappedUser != WH_KEYUSER_GLOBAL &&
                                wrappedUser != server->comm->client_id) {
                                ret = WH_ERROR_ACCESS;
                            }
#else
                            if (wrappedUser != server->comm->client_id) {
                                ret = WH_ERROR_ACCESS;
                            }
#endif
                        }
                        if (ret == WH_ERROR_OK) {
                            /* Force NONPERSISTABLE */
                            unwrapMeta.flags |= WH_NVM_FLAGS_NONPERSISTABLE;

                            /* Build cache ID using the ownership from
                             * the wrapped metadata. Global wrapped keys
                             * go to the global cache. */
                            unwrapMeta.id =
                                WH_MAKE_KEYID(req.type, wrappedUser,
                                              req.requestedId & WH_KEYID_MASK);

                            /* Auto-assign if erased */
                            if (WH_KEYID_ISERASED(unwrapMeta.id)) {
                                ret = wh_Server_ObjectGetUniqueId(
                                    server, &unwrapMeta.id);
                            }
                        }
                        if (ret == WH_ERROR_OK) {
                            ret = wh_Server_ObjectCacheAdd(server, &unwrapMeta,
                                                           keyBuf);
                        }
                        if (ret == WH_ERROR_OK) {
                            resp.id = wh_KeyId_TranslateToClient(unwrapMeta.id);
                        }

                        (void)WH_SERVER_NVM_UNLOCK(server);
                    }
                    resp.rc = ret;
                }
            }
            else
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
            {
                resp.rc = WH_ERROR_BADARGS;
            }

            /* Zero key material before returning */
            wc_ForceZero(keyBuf, sizeof(keyBuf));

            (void)wh_MessageObject_TranslateUnwrapCacheResponse(
                magic, &resp,
                (whMessageObject_UnwrapCacheResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_UNWRAP_EXPORT: {
            whMessageObject_UnwrapExportRequest  req;
            whMessageObject_UnwrapExportResponse resp;
            uint8_t*                             wrappedIn;
            uint8_t*                             keyOut;
            whKeyId                              kekId;
            whNvmMetadata                        unwrapMeta;
            uint8_t  keyBuf[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
            uint16_t keySz;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateUnwrapExportResponse(
                    magic, &resp,
                    (whMessageObject_UnwrapExportResponse*)resp_packet);
                break;
            }

            (void)wh_MessageObject_TranslateUnwrapExportRequest(
                magic, (whMessageObject_UnwrapExportRequest*)req_packet, &req);

            wrappedIn = (uint8_t*)req_packet + sizeof(req);
            keyOut    = (uint8_t*)resp_packet + sizeof(resp);

            /* KEK is always a crypto object regardless of wrapped object type
             */
            kekId = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.serverKekId);

            /* Validate client-controlled wrappedSz against actual packet size
             */
            {
                uint16_t availableSz = req_size - sizeof(req);
                if (req.wrappedSz > availableSz) {
                    resp.rc        = WH_ERROR_BADARGS;
                    *out_resp_size = sizeof(resp);
                    (void)wh_MessageObject_TranslateUnwrapExportResponse(
                        magic, &resp,
                        (whMessageObject_UnwrapExportResponse*)resp_packet);
                    break;
                }
            }

#ifndef NO_AES
#ifdef HAVE_AESGCM
            if (req.cipherType == WC_CIPHER_AES_GCM) {
                if (req.wrappedSz <
                    WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(unwrapMeta)) {
                    resp.rc = WH_ERROR_BADARGS;
                }
                else {
                    keySz = req.wrappedSz - WH_KEYWRAP_AES_GCM_HEADER_SIZE -
                            sizeof(unwrapMeta);

                    if ((uint32_t)sizeof(resp) + keySz >
                        WOLFHSM_CFG_COMM_DATA_LEN) {
                        resp.rc = WH_ERROR_BUFFER_SIZE;
                    }
                    else {
                        ret = WH_SERVER_NVM_LOCK(server);
                        if (ret == WH_ERROR_OK) {
                            ret = _AesGcmObjectUnwrap(
                                server, kekId, wrappedIn, req.wrappedSz,
                                &unwrapMeta, keyBuf, keySz);
                            /* Validate decrypted metadata length matches
                             * expected key size derived from packet
                             * structure */
                            if (ret == WH_ERROR_OK &&
                                unwrapMeta.len != keySz) {
                                ret = WH_ERROR_BADARGS;
                            }
                            /* Validate ownership */
                            if (ret == WH_ERROR_OK) {
                                uint16_t wrappedUser =
                                    WH_KEYID_USER(unwrapMeta.id);
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
                                if (wrappedUser != WH_KEYUSER_GLOBAL &&
                                    wrappedUser != server->comm->client_id) {
                                    ret = WH_ERROR_ACCESS;
                                }
#else
                                if (wrappedUser != server->comm->client_id) {
                                    ret = WH_ERROR_ACCESS;
                                }
#endif
                            }
                            if (ret == WH_ERROR_OK) {
                                /* Check exportable */
                                if (unwrapMeta.flags &
                                    WH_NVM_FLAGS_NONEXPORTABLE) {
                                    ret = WH_ERROR_ACCESS;
                                }
                            }
                            if (ret == WH_ERROR_OK) {
                                resp.keySz  = keySz;
                                resp.access = unwrapMeta.access;
                                resp.flags  = unwrapMeta.flags;
                                memcpy(resp.label, unwrapMeta.label,
                                       sizeof(resp.label));
                                memcpy(keyOut, keyBuf, keySz);
                            }

                            (void)WH_SERVER_NVM_UNLOCK(server);
                        }
                        resp.rc = ret;
                    }
                }
            }
            else
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
            {
                resp.rc = WH_ERROR_BADARGS;
            }

            /* Zero key material before returning */
            wc_ForceZero(keyBuf, sizeof(keyBuf));

            (void)wh_MessageObject_TranslateUnwrapExportResponse(
                magic, &resp,
                (whMessageObject_UnwrapExportResponse*)resp_packet);
            *out_resp_size = sizeof(resp) + resp.keySz;
        } break;
#endif /* WOLFHSM_CFG_KEYWRAP */

#ifdef WOLFHSM_CFG_DMA
        case WH_OBJECT_CACHE_ADD_DMA: {
            whMessageObject_CacheAddDmaRequest  req;
            whMessageObject_CacheAddDmaResponse resp;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateCacheAddDmaResponse(
                    magic, &resp,
                    (whMessageObject_CacheAddDmaResponse*)resp_packet);
                break;
            }

            /* translate request */
            (void)wh_MessageObject_TranslateCacheAddDmaRequest(
                magic, (whMessageObject_CacheAddDmaRequest*)req_packet, &req);

            /* set the metadata fields */
            meta->id = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);
            meta->access = req.access;
            meta->flags  = req.flags;
            if (req.obj.sz > UINT16_MAX) {
                resp.rc = WH_ERROR_BADARGS;
                (void)wh_MessageObject_TranslateCacheAddDmaResponse(
                    magic, &resp,
                    (whMessageObject_CacheAddDmaResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                break;
            }
            meta->len = (uint16_t)req.obj.sz;
            /* truncate label if it's too large */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                req.labelSz = WH_NVM_LABEL_LEN;
            }
            memcpy(meta->label, req.label, req.labelSz);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* get a new id if one wasn't provided */
                if (WH_KEYID_ISERASED(meta->id)) {
                    ret = wh_Server_ObjectGetUniqueId(server, &meta->id);
                }

                /* write the object using DMA */
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_ObjectCacheAddDmaChecked(server, meta,
                                                             req.obj.addr);
                    /* propagate bad address to client if DMA operation failed
                     */
                    if (ret != WH_ERROR_OK) {
                        resp.dmaAddrStatus.badAddr.addr = req.obj.addr;
                        resp.dmaAddrStatus.badAddr.sz   = req.obj.sz;
                    }
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */

            if (ret == WH_ERROR_OK) {
                /* Translate server keyId back to client format with flags */
                resp.id = wh_KeyId_TranslateToClient(meta->id);
            }
            resp.rc = ret;

            (void)wh_MessageObject_TranslateCacheAddDmaResponse(
                magic, &resp,
                (whMessageObject_CacheAddDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_OBJECT_CACHE_EXPORT_DMA: {
            whMessageObject_CacheExportDmaRequest  req;
            whMessageObject_CacheExportDmaResponse resp;
            whKeyId                                keyId;

            memset(&resp, 0, sizeof(resp));

            if (req_size < sizeof(req)) {
                resp.rc        = WH_ERROR_BADARGS;
                *out_resp_size = sizeof(resp);
                (void)wh_MessageObject_TranslateCacheExportDmaResponse(
                    magic, &resp,
                    (whMessageObject_CacheExportDmaResponse*)resp_packet);
                break;
            }

            /* translate request */
            (void)wh_MessageObject_TranslateCacheExportDmaRequest(
                magic, (whMessageObject_CacheExportDmaRequest*)req_packet,
                &req);

            keyId = wh_KeyId_TranslateFromClient(
                req.type, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_ObjectCacheExportDmaChecked(
                    server, keyId, req.obj.addr, req.obj.sz, meta);

                /* propagate bad address to client if DMA operation failed */
                if (ret != WH_ERROR_OK) {
                    resp.dmaAddrStatus.badAddr.addr = req.obj.addr;
                    resp.dmaAddrStatus.badAddr.sz   = req.obj.sz;
                }

                if (ret == WH_ERROR_OK) {
                    resp.len = meta->len;
                    memcpy(resp.label, meta->label, sizeof(meta->label));
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = ret;

            (void)wh_MessageObject_TranslateCacheExportDmaResponse(
                magic, &resp,
                (whMessageObject_CacheExportDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;
#endif /* WOLFHSM_CFG_DMA */

        default:
            ret = WH_ERROR_BADARGS;
            break;
    }

    return ret;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_SERVER */
