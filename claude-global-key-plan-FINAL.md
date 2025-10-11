# Global Keys Implementation Plan

## Overview

Implement global key support in wolfHSM, allowing keys to be accessible across multiple clients while maintaining existing per-client key isolation. Global keys use the existing USER field (USER=0) for identification, with the global flag serving as a client-to-server signal only.

**Feature Configuration**: All global key functionality is opt-in via `WOLFHSM_CFG_GLOBAL_KEYS` build macro.

## Architecture

### Key Translation Flow

**Local Key (existing behavior)**:
```
Client passes: keyId = 5
Server creates: WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, client_id=3, 5) = 0x1305
Stored: 0x1305 (TYPE=1, USER=3, ID=5)
```

**Global Key (new)**:
```
Client passes: keyId = WH_KEYID_GLOBAL | 5 = 0x0105
Server detects global flag, creates: WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 5) = 0x1005
Stored: 0x1005 (TYPE=1, USER=0, ID=5)
```

### Cache Architecture

Use unified cache abstraction (`whKeyCacheContext`) to eliminate code duplication:
- Server context embeds local cache
- NVM context embeds global cache (when `WOLFHSM_CFG_GLOBAL_KEYS` enabled)
- All cache operations work uniformly on `whKeyCacheContext*`
- Routing based on USER field: USER=0 → global, USER=client_id → local

## Implementation Steps

---

## Phase 0: Define Cache Abstraction

### 0.1: Define Cache Context Structure

**File**: `wolfhsm/wh_server.h`

Add before `whServerContext` definition:

```c
/**
 * @brief Unified key cache context
 *
 * Holds both regular and big cache arrays. Used for client-local caches
 * (embedded in whServerContext) and global caches (embedded in whNvmContext
 * when WOLFHSM_CFG_GLOBAL_KEYS is enabled).
 */
typedef struct whKeyCacheContext_t {
    whServerCacheSlot    cache[WOLFHSM_CFG_SERVER_KEYCACHE_COUNT];
    whServerBigCacheSlot bigCache[WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT];
} whKeyCacheContext;
```

### 0.2: Update Server Context

**File**: `wolfhsm/wh_server.h`

Modify `whServerContext` structure:

```c
/* BEFORE: */
struct whServerContext_t {
    whNvmContext* nvm;
    whCommServer  comm[1];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext* crypto;
    whServerCacheSlot      cache[WOLFHSM_CFG_SERVER_KEYCACHE_COUNT];
    whServerBigCacheSlot   bigCache[WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT];
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    whServerSheContext* she;
#endif
#endif
    // ... rest
};

/* AFTER: */
struct whServerContext_t {
    whNvmContext* nvm;
    whCommServer  comm[1];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext* crypto;
    whKeyCacheContext localCache;  /* Unified cache structure */
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    whServerSheContext* she;
#endif
#endif
    // ... rest
};
```

### 0.3: Update NVM Context

**File**: `wolfhsm/wh_nvm.h`

Add forward declaration at top:

```c
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_GLOBAL_KEYS)
typedef struct whKeyCacheContext_t whKeyCacheContext;
#endif
```

Modify `whNvmContext` structure:

```c
typedef struct whNvmContext_t {
    whNvmCb *cb;
    void* context;
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_GLOBAL_KEYS)
    whKeyCacheContext globalCache;  /* Global key cache */
#endif
} whNvmContext;
```

### 0.4: Update Cache References

**File**: `src/wh_server_keystore.c` (and any other files accessing cache)

Replace all references:
- `server->cache[` → `server->localCache.cache[`
- `server->bigCache[` → `server->localCache.bigCache[`

Use search/replace across entire codebase.

### 0.5: Add Cache Helper Functions

**File**: `src/wh_server_keystore.c`

Add at top of file (after includes):

```c
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/**
 * @brief Check if keyId represents a global key (USER == 0)
 */
static int _IsGlobalKey(whKeyId keyId)
{
    return (WH_KEYID_USER(keyId) == WH_KEYUSER_GLOBAL);
}

/**
 * @brief Get the appropriate cache context based on keyId
 */
static whKeyCacheContext* _GetCacheContext(whServerContext* server, whKeyId keyId)
{
    if (_IsGlobalKey(keyId)) {
        return &server->nvm->globalCache;
    }
    return &server->localCache;
}
#else
/* When global keys disabled, always use local cache */
static whKeyCacheContext* _GetCacheContext(whServerContext* server, whKeyId keyId)
{
    (void)keyId;
    return &server->localCache;
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */
```

Add generic cache operation functions:

```c
/**
 * @brief Find a key in the specified cache context
 */
static int _FindInKeyCache(whKeyCacheContext* ctx, whKeyId keyId,
                           int* out_index, int* out_big,
                           uint8_t** out_buffer, whNvmMetadata** out_meta)
{
    int ret = WH_ERROR_NOTFOUND;
    int i;
    int index = -1;
    int big = -1;
    whNvmMetadata* meta = NULL;
    uint8_t* buffer = NULL;

    /* Search regular cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (ctx->cache[i].meta->id == keyId) {
            big = 0;
            index = i;
            meta = ctx->cache[i].meta;
            buffer = ctx->cache[i].buffer;
            break;
        }
    }

    /* Search big cache if not found */
    if (index == -1) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == keyId) {
                big = 1;
                index = i;
                meta = ctx->bigCache[i].meta;
                buffer = ctx->bigCache[i].buffer;
                break;
            }
        }
    }

    /* Set output parameters if found */
    if (index != -1) {
        if (out_index != NULL) *out_index = index;
        if (out_big != NULL) *out_big = big;
        if (out_meta != NULL) *out_meta = meta;
        if (out_buffer != NULL) *out_buffer = buffer;
        ret = WH_ERROR_OK;
    }

    return ret;
}

/**
 * @brief Get an available cache slot from the specified cache context
 */
static int _GetKeyCacheSlot(whKeyCacheContext* ctx, uint16_t keySz,
                            uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int foundIndex = -1;
    int i;

    if (ctx == NULL || outBuf == NULL || outMeta == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Determine which cache to use based on key size */
    if (keySz <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* Search regular cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed key to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (ctx->cache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* Zero slot and return pointers */
        if (foundIndex >= 0) {
            memset(&ctx->cache[foundIndex], 0, sizeof(whServerCacheSlot));
            *outBuf = ctx->cache[foundIndex].buffer;
            *outMeta = ctx->cache[foundIndex].meta;
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

        /* If no empty slots, find committed key to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (ctx->bigCache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* Zero slot and return pointers */
        if (foundIndex >= 0) {
            memset(&ctx->bigCache[foundIndex], 0, sizeof(whServerBigCacheSlot));
            *outBuf = ctx->bigCache[foundIndex].buffer;
            *outMeta = ctx->bigCache[foundIndex].meta;
        }
    }

    if (foundIndex == -1) {
        return WH_ERROR_NOSPACE;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Evict a key from the specified cache context
 */
static int _EvictKeyFromCache(whKeyCacheContext* ctx, whKeyId keyId)
{
    whNvmMetadata* meta = NULL;
    int ret = _FindInKeyCache(ctx, keyId, NULL, NULL, NULL, &meta);

    if (ret == WH_ERROR_OK && meta != NULL) {
        meta->id = WH_KEYID_ERASED;
    }

    return ret;
}

/**
 * @brief Mark a cached key as committed
 */
static int _MarkKeyCommitted(whKeyCacheContext* ctx, whKeyId keyId, int committed)
{
    int index = -1;
    int big = -1;
    int ret = _FindInKeyCache(ctx, keyId, &index, &big, NULL, NULL);

    if (ret == WH_ERROR_OK) {
        if (big == 0) {
            ctx->cache[index].commited = committed;
        } else {
            ctx->bigCache[index].commited = committed;
        }
    }

    return ret;
}

/**
 * @brief Legacy wrapper for backward compatibility
 */
static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta)
{
    return _FindInKeyCache(&server->localCache, keyId, out_index, out_big,
                           out_buffer, out_meta);
}
```

---

## Phase 1: Define Global Key Flag

### 1.1: Add Global Key Constants

**File**: `wolfhsm/wh_common.h`

Add after existing key macros:

```c
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/* Global key flag - client-to-server signal only, NOT stored in keyId */
/* This flag is stripped before storage and translated to USER=0 encoding */
#define WH_KEYID_GLOBAL 0x0100  /* Bit 8: temporary flag for client requests */

/* Helper macros */
#define WH_KEYID_ISGLOBAL(_kid) (((_kid) & WH_KEYID_GLOBAL) != 0)

/* Reserve USER=0 for global keys */
#define WH_KEYUSER_GLOBAL 0

/* Helper to check if a keyId represents a global key (by USER field) */
#define WH_KEYID_ISGLOBALKEY(_kid) (WH_KEYID_USER(_kid) == WH_KEYUSER_GLOBAL)
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */
```

### 1.2: Add Build Configuration

**File**: `wolfhsm/wh_settings.h`

Add with other feature flags:

```c
/* Global key support - allows keys to be shared across clients */
/* #define WOLFHSM_CFG_GLOBAL_KEYS */
```

---

## Phase 2: Update Keystore Public Functions

### 2.1: Update wh_Server_KeystoreGetUniqueId

**File**: `src/wh_server_keystore.c`

Modify to check appropriate cache based on USER field:

```c
int wh_Server_KeystoreGetUniqueId(whServerContext* server, whNvmId* inout_id)
{
    int     i;
    int     ret = 0;
    whNvmId id;
    whKeyId key_id = *inout_id;
    int     type   = WH_KEYID_TYPE(key_id);
    int     user   = WH_KEYID_USER(key_id);
    whNvmId buildId;
    whNvmId nvmId = 0;
    whNvmId keyCount;

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    whKeyCacheContext* ctx = _GetCacheContext(server, key_id);
#else
    whKeyCacheContext* ctx = &server->localCache;
#endif

    /* Try every index until we find a unique one */
    for (id = WH_KEYID_IDMAX; id > WH_KEYID_ERASED; id--) {
        buildId = WH_MAKE_KEYID(type, user, id);

        /* Check against cache keys using unified cache functions */
        ret = _FindInKeyCache(ctx, buildId, NULL, NULL, NULL, NULL);
        if (ret == WH_ERROR_OK) {
            /* Found in cache, try next ID */
            continue;
        }

        /* Check if keyId exists in NVM */
        ret = wh_Nvm_List(server->nvm, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_ANY,
                          buildId, &keyCount, &nvmId);
        /* Break if we didn't find a match */
        if (ret == WH_ERROR_NOTFOUND || nvmId != buildId)
            break;
    }

    /* Check if we've run out of ids */
    if (id > WH_KEYID_IDMAX)
        ret = WH_ERROR_NOSPACE;

    /* Return found id */
    if (ret == 0)
        *inout_id = buildId;

    return ret;
}
```

### 2.2: Update wh_Server_KeystoreCacheKey

```c
int wh_Server_KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                               uint8_t* in)
{
    uint8_t* buffer;
    whNvmMetadata* slotMeta;
    int ret;

    if (server == NULL || meta == NULL || in == NULL ||
        WH_KEYID_ISERASED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    whKeyCacheContext* ctx = _GetCacheContext(server, meta->id);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Handle cross-cache eviction: if same ID exists in other cache, evict it */
    whKeyCacheContext* otherCtx = _IsGlobalKey(meta->id) ?
                                  &server->localCache : &server->nvm->globalCache;
    (void)_EvictKeyFromCache(otherCtx, meta->id);
#endif

    /* Get cache slot */
    ret = _GetKeyCacheSlot(ctx, meta->len, &buffer, &slotMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Copy data and metadata */
    memcpy(buffer, in, meta->len);
    memcpy(slotMeta, meta, sizeof(whNvmMetadata));

    /* Check if already committed in NVM */
    if (wh_Nvm_GetMetadata(server->nvm, meta->id, meta) == WH_ERROR_NOTFOUND) {
        _MarkKeyCommitted(ctx, meta->id, 0);  /* Not committed */
    } else {
        _MarkKeyCommitted(ctx, meta->id, 1);  /* Committed */
    }

    return WH_ERROR_OK;
}
```

### 2.3: Update wh_Server_KeystoreFreshenKey

```c
int wh_Server_KeystoreFreshenKey(whServerContext* server, whKeyId keyId,
                                 uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int ret;
    whNvmMetadata tmpMeta[1];

    if (server == NULL || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);

    /* Try to find in cache */
    ret = _FindInKeyCache(ctx, keyId, NULL, NULL, outBuf, outMeta);
    if (ret != WH_ERROR_OK) {
        /* Not in cache, check NVM */
        ret = wh_Nvm_GetMetadata(server->nvm, keyId, tmpMeta);
        if (ret == WH_ERROR_OK) {
            /* Key found in NVM, get a free cache slot */
            ret = _GetKeyCacheSlot(ctx, tmpMeta->len, outBuf, outMeta);
            if (ret == WH_ERROR_OK) {
                /* Read the key from NVM into the cache slot */
                ret = wh_Nvm_Read(server->nvm, keyId, 0, tmpMeta->len, *outBuf);
                if (ret == WH_ERROR_OK) {
                    memcpy(*outMeta, tmpMeta, sizeof(whNvmMetadata));
                }
            }
        }
    }

    return ret;
}
```

### 2.4: Update wh_Server_KeystoreReadKey

```c
int wh_Server_KeystoreReadKey(whServerContext* server, whKeyId keyId,
                              whNvmMetadata* outMeta, uint8_t* out,
                              uint32_t* outSz)
{
    int ret;
    uint8_t* buffer;
    whNvmMetadata* cacheMeta;
    whNvmMetadata meta[1];

    if (server == NULL || outSz == NULL ||
        (WH_KEYID_ISERASED(keyId) && (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_SHE))) {
        return WH_ERROR_BADARGS;
    }

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);

    /* Try to find in cache */
    ret = _FindInKeyCache(ctx, keyId, NULL, NULL, &buffer, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        /* Found in cache */
        if (cacheMeta->len > *outSz) {
            return WH_ERROR_NOSPACE;
        }
        if (outMeta != NULL) {
            memcpy(outMeta, cacheMeta, sizeof(whNvmMetadata));
        }
        if (out != NULL) {
            memcpy(out, buffer, cacheMeta->len);
        }
        *outSz = cacheMeta->len;
        return WH_ERROR_OK;
    }

    /* Not in cache, try NVM */
    ret = wh_Nvm_GetMetadata(server->nvm, keyId, meta);
    if (ret == 0) {
        *outSz = meta->len;
        if (outMeta != NULL) {
            memcpy(outMeta, meta, sizeof(whNvmMetadata));
        }
        if (out != NULL) {
            ret = wh_Nvm_Read(server->nvm, keyId, 0, *outSz, out);
        }
        /* Cache key if free slot available */
        if (ret == 0 && out != NULL) {
            (void)wh_Server_KeystoreCacheKey(server, meta, out);
        }
    }

#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* Handle empty SHE master ECU key special case */
    if ((ret == WH_ERROR_NOTFOUND) &&
        (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_SHE) &&
        (WH_KEYID_ID(keyId) == WH_SHE_MASTER_ECU_KEY_ID)) {
        memset(out, 0, WH_SHE_KEY_SZ);
        *outSz = WH_SHE_KEY_SZ;
        if (outMeta != NULL) {
            memset(outMeta, 0, sizeof(meta));
            meta->len = WH_SHE_KEY_SZ;
            meta->id  = keyId;
        }
        ret = 0;
    }
#endif

    return ret;
}
```

### 2.5: Update wh_Server_KeystoreEvictKey

```c
int wh_Server_KeystoreEvictKey(whServerContext* server, whNvmId keyId)
{
    if (server == NULL || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    return _EvictKeyFromCache(ctx, keyId);
}
```

### 2.6: Update wh_Server_KeystoreCommitKey

```c
int wh_Server_KeystoreCommitKey(whServerContext* server, whNvmId keyId)
{
    uint8_t* slotBuf;
    whNvmMetadata* slotMeta;
    int ret;

    if (server == NULL || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);

    ret = _FindInKeyCache(ctx, keyId, NULL, NULL, &slotBuf, &slotMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, slotMeta,
                                          slotMeta->len, slotBuf);
        if (ret == 0) {
            _MarkKeyCommitted(ctx, keyId, 1);
        }
    }

    return ret;
}
```

### 2.7: Update wh_Server_KeystoreEraseKey

```c
int wh_Server_KeystoreEraseKey(whServerContext* server, whNvmId keyId)
{
    if (server == NULL || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    /* Evict from appropriate cache */
    (void)wh_Server_KeystoreEvictKey(server, keyId);

    /* Destroy in NVM */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &keyId);
}
```

### 2.8: Update DMA Functions (if applicable)

Update `wh_Server_KeystoreCacheKeyDma` and `wh_Server_KeystoreExportKeyDma` similarly to use `_GetCacheContext()`.

---

## Phase 3: Request Handler Translation

### 3.1: Add Translation Macro

**File**: `src/wh_server_keystore.c`

Add at top of file:

```c
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/* Translate client keyId (may have WH_KEYID_GLOBAL flag) to server keyId */
#define WH_SERVER_TRANSLATE_KEYID(_type, _server_ctx, _client_keyid) \
    ((_client_keyid & WH_KEYID_GLOBAL) ? \
     WH_MAKE_KEYID(_type, WH_KEYUSER_GLOBAL, _client_keyid & WH_KEYID_MASK) : \
     WH_MAKE_KEYID(_type, (_server_ctx)->comm->client_id, _client_keyid & WH_KEYID_MASK))
#else
/* When global keys disabled, always use client_id */
#define WH_SERVER_TRANSLATE_KEYID(_type, _server_ctx, _client_keyid) \
    WH_MAKE_KEYID(_type, (_server_ctx)->comm->client_id, _client_keyid & WH_KEYID_MASK)
#endif
```

### 3.2: Update Key Request Handlers

In `wh_Server_HandleKeyRequest()`, update all cases to use translation macro:

**WH_KEY_CACHE**:
```c
case WH_KEY_CACHE: {
    /* ... existing request translation ... */

    /* CHANGE: Use translation macro */
    meta->id = WH_SERVER_TRANSLATE_KEYID(WH_KEYTYPE_CRYPTO, server, req.id);

    /* ... rest of handler unchanged ... */
}
```

Apply to all key operation handlers:
- `WH_KEY_CACHE`
- `WH_KEY_CACHE_DMA`
- `WH_KEY_EXPORT`
- `WH_KEY_EXPORT_DMA`
- `WH_KEY_EVICT`
- `WH_KEY_COMMIT`
- `WH_KEY_ERASE`
- `WH_KEY_WRAP` (also translate `serverKeyId` field)
- `WH_KEY_UNWRAPEXPORT` (also translate `serverKeyId` field)
- `WH_KEY_UNWRAPCACHE` (also translate `serverKeyId` field)

---

## Phase 4: Update Crypto Operations

### 4.1: Add New Translation Macro

**File**: `src/wh_server_crypto.c`

Add at top of file:

```c
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/* Translate client keyId to server keyId for crypto operations */
#define WH_CRYPTO_TRANSLATE_KEYID(_ctx, _client_keyid) \
    WH_SERVER_TRANSLATE_KEYID(WH_KEYTYPE_CRYPTO, _ctx, _client_keyid)
#else
#define WH_CRYPTO_TRANSLATE_KEYID(_ctx, _client_keyid) \
    WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, (_ctx)->comm->client_id, _client_keyid)
#endif
```

### 4.2: Update All Crypto Operations

Search for pattern: `WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, ctx->comm->client_id,`

Replace with: `WH_CRYPTO_TRANSLATE_KEYID(ctx,`

Approximately 70 locations in functions:
- AES operations (encrypt, decrypt, GCM, CBC, CTR, etc.)
- RSA operations (sign, verify, encrypt, decrypt, keygen)
- ECC operations (sign, verify, keygen, ECDH, shared secret)
- Curve25519 operations
- CMAC operations
- Key generation functions
- Crypto callback handlers

**Example**:
```c
/* BEFORE: */
whKeyId keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

/* AFTER: */
whKeyId keyId = WH_CRYPTO_TRANSLATE_KEYID(ctx, req.keyId);
```

---

## Phase 5: SHE and Counter Operations

### Decision: Disable Global Keys for SHE and Counters

No change necessary for SHE or counter layer - keep it as-is.

---

## Phase 6: Client API

### 6.1: Add Client Macros

**File**: `wolfhsm/wh_client.h`

Add with other key macros:

```c
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/* Mark a key ID as global (accessible to all clients) */
#define WH_CLIENT_KEYID_GLOBAL(_id) (WH_KEYID_GLOBAL | (_id))

/* Check if a key ID has global flag */
#define WH_CLIENT_KEYID_ISGLOBAL(_id) WH_KEYID_ISGLOBAL(_id)

/* Strip global flag from key ID */
#define WH_CLIENT_KEYID_LOCAL(_id) ((_id) & ~WH_KEYID_GLOBAL)
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */
```

---

## Phase 7: Documentation

### 7.1: Create Global Keys Documentation

**File**: `docs/global-keys.md` (create new)

```markdown
# Global Keys

## Overview

Global keys allow cryptographic keys to be shared across multiple wolfHSM clients
while maintaining per-client isolation for non-global keys.

**Configuration**: Enable with `WOLFHSM_CFG_GLOBAL_KEYS` build macro.

## Architecture

Global keys use `USER=0` in the keyId encoding:
- Global keys: `USER=0` (e.g., keyId 0x1005)
- Client 3 local keys: `USER=3` (e.g., keyId 0x1305)

The `WH_KEYID_GLOBAL` flag is a client-to-server signal only, translated
to `USER=0` by the server. The flag is not stored.

## Usage

```c
#ifdef WOLFHSM_CFG_GLOBAL_KEYS

/* Cache a global key */
ret = wh_Client_KeyCache(client, WH_CLIENT_KEYID_GLOBAL(5), key, keySz, ...);

/* Cache a local key */
ret = wh_Client_KeyCache(client, 5, key, keySz, ...);

/* Use global key in crypto operation */
ret = wh_Client_AesEncrypt(client, WH_CLIENT_KEYID_GLOBAL(5), ...);

#endif
```

## Security Considerations

- Global keys bypass client isolation by design
- Ensure export protection flags still enforced (WH_NVM_FLAGS_NONEXPORTABLE)
- Access control flags still enforced (whNvmAccess)

## Configuration

- `WOLFHSM_CFG_GLOBAL_KEYS`: Enable global key support (disabled by default)
- `WOLFHSM_CFG_SERVER_KEYCACHE_COUNT`: Size of both global and local caches
- `WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT`: Big cache size (both global and local)

## Limitations

- SHE keys and counters do not support global flag (client-specific only)
- Global and local caches use same size configuration
```

### 7.2: Update CLAUDE.md

**File**: `CLAUDE.md`

Add section:

```markdown
## Global Keys (Optional Feature)

When `WOLFHSM_CFG_GLOBAL_KEYS` is defined, wolfHSM supports global keys that
are accessible across all clients:

- Use `WH_CLIENT_KEYID_GLOBAL(id)` to mark a key as global
- Global keys use `USER=0` encoding internally
- Local keys remain isolated per-client
- See `docs/global-keys.md` for details
```

---

## Phase 8: Testing

### 8.1: Create Test File

**File**: `test/wh_test_multiclient.c`

add comprehensive test functionality with new harness for multi-client operations. It should instantiate a "sequential test" just like that in wh_test_clientserver.c using shared memory transport, the only difference being two clients are set up, and the server processes their corresponding server contexts round-robin in a processing loop. Tests should cover:

1. **Basic Global Key Operations**
   - Client A caches global key
   - Client B reads same global key
   - Verify data matches

2. **Local Key Isolation**
   - Client A caches local key ID 5
   - Client B caches local key ID 5
   - Verify different keys (isolated)

3. **Mixed Global/Local**
   - Cache global key 5, local key 6 on Client A
   - Cache global key 5, local key 6 on Client B
   - Verify key 5 shared, key 6 isolated

5. **NVM Persistence**
   - Cache global key
   - Commit to NVM
   - Evict from cache
   - Reload from NVM via different client
   - Verify data matches

6. **Export Protection**
   - Cache global key with WH_NVM_FLAGS_NONEXPORTABLE
   - Try to export from different client
   - Verify export blocked

8. **No Cross-Cache interference **
   - Cache key 5 as global
   - Cache key 5 as local
   - Verify correct cache used based on presense of global flag


---

## Implementation Checklist

- [ ] **Phase 0**: Cache Abstraction
  - [ ] Define `whKeyCacheContext`
  - [ ] Update `whServerContext`
  - [ ] Update `whNvmContext` with `#ifdef WOLFHSM_CFG_GLOBAL_KEYS`
  - [ ] Update all `server->cache` references
  - [ ] Add `_GetCacheContext()` with feature guard
  - [ ] Add generic cache functions

- [ ] **Phase 1**: Global Key Flag
  - [ ] Add `WH_KEYID_GLOBAL` and helpers with `#ifdef`
  - [ ] Add build config to `wh_settings.h`

- [ ] **Phase 2**: Keystore Functions
  - [ ] Update all 7 keystore functions to use cache abstraction

- [ ] **Phase 3**: Request Handler
  - [ ] Add `WH_SERVER_TRANSLATE_KEYID` macro with feature guard
  - [ ] Update 10 key operation handlers

- [ ] **Phase 4**: Crypto Operations
  - [ ] Add `WH_CRYPTO_TRANSLATE_KEYID` macro with feature guard
  - [ ] Update ~70 crypto operation sites

- [ ] **Phase 5**: SHE/Counter
  - [ ] Strip global flag for SHE keys
  - [ ] Strip global flag for counters

- [ ] **Phase 6**: Client API
  - [ ] Add client macros with `#ifdef`
  - [ ] Update docstrings

- [ ] **Phase 7**: Documentation
  - [ ] Create `docs/global-keys.md`
  - [ ] Update `CLAUDE.md`

- [ ] **Phase 8**: Testing
  - [ ] Create `test/wh_test_multiclient.c`
  - [ ] Implement test cases
  - [ ] Test with feature enabled
  - [ ] Test with feature disabled, verify no regressions

---

## Build Configuration Summary

**Default**: Global keys disabled

**Enable**: Define `WOLFHSM_CFG_GLOBAL_KEYS` in build configuration

**Effect when disabled**:
- No global cache allocated in `whNvmContext`
- `WH_KEYID_GLOBAL` flag undefined
- `_GetCacheContext()` always returns local cache
- Translation macros ignore flag
- Zero code size overhead

**Effect when enabled**:
- Global cache embedded in `whNvmContext`
- Global flag recognized in client requests
- Keys with `USER=0` routed to global cache
- ~2-4KB additional memory for global cache

---

## Success Criteria

1. Client can cache a key with global flag (when feature enabled)
2. Different client can access the same global key
3. Local keys remain isolated per-client
4. All existing tests pass with feature enabled and disabled
5. New global key tests pass
6. Zero code duplication (unified cache abstraction)
7. Feature is completely opt-in via build macro
8. No overhead when feature disabled

---

## Implementation Notes

### USER=0 Reservation

- Verify client IDs in existing code don't use 0
- Add assertion in server initialization: `assert(server->comm->client_id > 0)`
- Document in code and user docs


### Testing Strategy

- Test with feature enabled and disabled
- Verify backward compatibility
- Use Address Sanitizer (`ASAN=1`) during testing
- Test all crypto operations with both global and local keys
- Test with the following command: `cd test && make -j DMA=1 SHE=1 && make run`. To build with the new feature define it in test/config/wolfhsm_cfg.h. Omit this to test without it. Ensure you clean after modifying this file

### Code Review Points

- Verify all `#ifdef WOLFHSM_CFG_GLOBAL_KEYS` guards complete
- Verify translation macros handle flag correctly
- Verify no references to raw cache arrays (use `_GetCacheContext()`)
- Verify SHE/Counter operations strip global flag
- Check for memory leaks (global cache is static, should be none)
