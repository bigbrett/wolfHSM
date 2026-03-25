# Wrapped Cached Certificates

## Overview

This documents the "wrapped certificate" use case, showing how to leverage the
certificate manager to use trusted root certificates that live in the server's
**keystore cache** (RAM) after being unwrapped via keywrap functionality,
rather than exclusively in **NVM** (flash). A root certificate is wrapped
(AES-GCM encrypted) by the server, handed back to the client as an opaque blob,
and later unwrapped into the server's key cache on demand. Once cached, it can
be used in all certificate verification paths — standard, DMA, and ACERT —
exactly like an NVM-resident root certificate.

This is useful when a client needs to use a trusted root for verification but
does not want to (or cannot) commit it to NVM. The wrapped blob can be stored
cheaply on the client side, while the server only holds the unwrapped plaintext
in its volatile cache for as long as it is needed.

## High-Level Usage

The lifecycle has three stages: **wrap**, **unwrap-and-cache**, and **use**.

### 1. Provision a wrapping key (KEK)

Before wrapping anything the server needs an AES-256 key to use as the
key-encryption key. Cache it on the server with the `WH_NVM_FLAGS_USAGE_WRAP`
flag:

```c
whKeyId kekId = 10;
uint8_t kek[32] = { /* 256-bit AES key */ };

wh_Client_KeyCache(client,
                   WH_NVM_FLAGS_USAGE_WRAP, NULL, 0,
                   kek, sizeof(kek), &kekId);
```

> **Note:** This is an example only. In production, the KEK is normally
> provisioned and protected by target-specific hardware and should never be
> hardcoded.

The KEK is now sitting in the server's `localCache` (or `globalCache` if marked
global), indexed by `kekId`.

### 2. Wrap the certificate

Call `wh_Client_CertWrap` with the raw certificate DER and the KEK's ID. The
server encrypts the certificate using AES-GCM and returns the wrapped blob:

```c
uint8_t  wrappedCert[2048];
uint16_t wrappedCertSz = sizeof(wrappedCert);

/* Build metadata: id embeds TYPE=WRAPPED and the client's USER id;
 * caller controls flags, access, and optionally label */
whNvmMetadata certMeta = {0};
certMeta.id     = WH_CLIENT_KEYID_MAKE_WRAPPED_META(
    client->comm->client_id, 5);
certMeta.flags  = WH_NVM_FLAGS_USAGE_ANY;
certMeta.access = WH_NVM_ACCESS_ANY;

wh_Client_CertWrap(client, WC_CIPHER_AES_GCM, kekId,
                    rootCaCert, rootCaCertLen,
                    &certMeta,
                    wrappedCert, &wrappedCertSz);
```

After this call:

| Data | Location |
|---|---|
| KEK | Server key cache (`localCache[kekId]`) |
| Wrapped cert blob (ciphertext + GCM tag + IV + metadata) | Client memory (`wrappedCert` buffer) |
| Raw certificate | Nowhere on the server — only the client supplied it transiently |

The client can now persist `wrappedCert` to its own storage (file, flash,
external memory, etc.).

### 3. Unwrap and cache the certificate on the server

When the client needs the root for verification, it pushes the wrapped blob back
to the server:

```c
whKeyId cachedCertId = WH_KEYID_ERASED;

wh_Client_CertUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                              wrappedCert, wrappedCertSz,
                              &cachedCertId);
```

The server decrypts the blob using the KEK, verifies the GCM authentication
tag, and places the plaintext certificate into its key cache. The returned
`cachedCertId` is the server-internal key ID (with `TYPE=WH_KEYTYPE_WRAPPED`
already encoded).

After this call:

| Data | Location |
|---|---|
| KEK | Server key cache |
| Plaintext certificate | Server key cache (`localCache[cachedCertId]`) |
| Wrapped cert blob | Still in client memory (unchanged) |

### 4. Use the cached cert for verification

Pass the cached cert's ID — decorated with the wrapped flag — as the trusted
root to any verify API:

```c
int32_t verifyResult;

wh_Client_CertVerify(client,
                      intermediateCert, intermediateCertLen,
                      WH_CLIENT_KEYID_MAKE_WRAPPED(cachedCertId),
                      &verifyResult);
```

`WH_CLIENT_KEYID_MAKE_WRAPPED(cachedCertId)` sets bit 9
(`WH_KEYID_CLIENT_WRAPPED_FLAG = 0x0200`) on the ID the client sends to the
server. This is the signal that tells the server "this root cert is in the
cache, not in NVM."

The same pattern works for:
- `wh_Client_CertVerifyDma` (DMA path)
- `wh_Client_CertReadTrusted` / `wh_Client_CertReadTrustedDma` (read-back a
  cached cert by passing `WH_CLIENT_KEYID_MAKE_WRAPPED(cachedCertId)` as the
  `id` parameter)
- `wh_Client_CertVerifyAcert` / `wh_Client_CertVerifyAcertDma` (attribute certs)

### 5. Cleanup

Evict the cached cert and KEK when done:

```c
wh_Client_KeyEvict(client, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedCertId));
wh_Client_KeyEvict(client, kekId);
```

## Low-Level Implementation Details

### Client-side functions

Nine thin wrappers in `src/wh_client_cert.c` (guarded by
`WOLFHSM_CFG_KEYWRAP`), mirroring the Key wrap/unwrap API:

- **`wh_Client_CertWrap`** / **`wh_Client_CertWrapRequest`** /
  **`wh_Client_CertWrapResponse`** — Wrap a certificate. Accepts a
  caller-provided `whNvmMetadata*` (with `id`, `flags`, `access`, and
  optionally `label` set by the caller), sets `meta->len = certSz`, then
  delegates to the corresponding `wh_Client_KeyWrap*` function. The metadata's
  `id` field must have `TYPE=WH_KEYTYPE_WRAPPED` encoded via
  `WH_CLIENT_KEYID_MAKE_WRAPPED_META`.

- **`wh_Client_CertUnwrapAndExport`** / **`wh_Client_CertUnwrapAndExportRequest`** /
  **`wh_Client_CertUnwrapAndExportResponse`** — Unwrap a wrapped certificate
  and export both the plaintext certificate and its metadata back to the client.
  Delegates to the corresponding `wh_Client_KeyUnwrapAndExport*` function.

- **`wh_Client_CertUnwrapAndCache`** / **`wh_Client_CertUnwrapAndCacheRequest`** /
  **`wh_Client_CertUnwrapAndCacheResponse`** — Unwrap and cache on the server.
  Delegates to the corresponding `wh_Client_KeyUnwrapAndCache*` function.
  Returns the server-assigned cache slot ID in `*out_certId`.

All functions accept an `enum wc_CipherType cipherType` parameter (e.g.
`WC_CIPHER_AES_GCM`) to specify the wrapping cipher. The blocking variants
call their respective Request/Response functions in a do-while-NOTREADY loop.

These are pure convenience; a caller could use `wh_Client_KeyWrap*` /
`wh_Client_KeyUnwrapAndExport*` / `wh_Client_KeyUnwrapAndCache*` directly if
it needed custom metadata.

### Server-side routing (the key change)

#### `wh_Server_CertReadTrusted` (`src/wh_server_cert.c`)

Previously accepted only `whNvmId` and always read from NVM. Now accepts
`whKeyId` and branches on the TYPE field:

```
if WH_KEYID_TYPE(id) == WH_KEYTYPE_WRAPPED
    → wh_Server_KeystoreReadKey(server, id, &meta, cert, &sz)   // cache path
else
    → wh_Nvm_GetMetadata / wh_Nvm_Read                          // NVM path (unchanged)
```

`wh_Server_KeystoreReadKey` looks up the key in the server's `localCache` (or
`globalCache` if global keys are enabled and the USER field is 0). It copies
both the metadata and the raw data into the caller's buffers.

#### `wh_Server_CertVerify` / `wh_Server_CertVerifyAcert`

Signature changed from `whNvmId trustedRootId` to `whKeyId trustedRootId`.
Internally they just call `wh_Server_CertReadTrusted`, which now handles the
routing.

#### Request handlers in `wh_Server_HandleCertRequest`

Every handler that accepts a trusted root ID (`READTRUSTED`, `VERIFY`,
`READTRUSTED_DMA`, `VERIFY_DMA`, `VERIFY_ACERT`, `VERIFY_ACERT_DMA`) was
updated with the same pattern:

1. **Translate the client ID**: If the incoming `req.id` (or
   `req.trustedRootId`) has `WH_KEYID_CLIENT_WRAPPED_FLAG` set, call
   `wh_KeyId_TranslateFromClient(WH_KEYTYPE_WRAPPED, server->comm->client_id, req.id)`
   to produce a full server-internal key ID with `TYPE=WH_KEYTYPE_WRAPPED`,
   `USER=client_id`, and the bare key `ID` in the low byte.

2. **Branch on key type** for the read/verify:
   - **Cache path** (`WH_KEYID_TYPE(certId) == WH_KEYTYPE_WRAPPED`): Calls
     `wh_Server_KeystoreReadKey` to fetch the cert from the cache. Checks
     `WH_NVM_FLAGS_NONEXPORTABLE` on the metadata for read-back requests.
   - **NVM path** (original, `WH_KEYID_TYPE != WH_KEYTYPE_WRAPPED`): Unchanged
     behavior — reads from flash via `wh_Nvm_GetMetadata` / `wh_Nvm_Read`.

### Key ID encoding walkthrough

Consider a client with `client_id = 1` wrapping a cert with bare ID `5`:

| Stage | Value | Encoding |
|---|---|---|
| `WH_CLIENT_KEYID_MAKE_WRAPPED_META(1, 5)` | `0x4105` | TYPE=4 (WRAPPED), USER=1, ID=5 — stored *inside* the wrapped blob metadata |
| Server returns `cachedCertId` after unwrap | `0x4105` | Same — the server preserved the metadata ID |
| Client sends `WH_CLIENT_KEYID_MAKE_WRAPPED(0x4105)` | `0x4305` | Bit 9 (0x0200) set as client flag |
| Server calls `wh_KeyId_TranslateFromClient(...)` | `0x4105` | Flag stripped, TYPE=WRAPPED confirmed, USER=1, ID=5 |
| `WH_KEYID_TYPE(0x4105)` | `4` | Equals `WH_KEYTYPE_WRAPPED` (4) → routes to cache |

### Data stored at each point

| Point in flow | Server key cache | Server NVM | Client memory |
|---|---|---|---|
| After `KeyCache` (KEK) | KEK at `kekId` | — | — |
| After `CertWrap` | KEK at `kekId` | — | Wrapped blob (ciphertext + tag + IV + metadata) |
| After `CertUnwrapAndCache` | KEK at `kekId`, plaintext cert at `cachedCertId` | — | Wrapped blob (unchanged) |
| During `CertVerify` | KEK, plaintext cert (read into stack buffer `root_cert[WOLFHSM_CFG_MAX_CERT_SIZE]` by `CertReadTrusted`) | — | — |
| After `KeyEvict` (cert) | KEK at `kekId` | — | Wrapped blob |
| After `KeyEvict` (KEK) | — | — | Wrapped blob |

## Interaction with Locking and Thread Safety

### The NVM lock (`WH_SERVER_NVM_LOCK` / `WH_SERVER_NVM_UNLOCK`)

When `WOLFHSM_CFG_THREADSAFE` is defined, `WH_SERVER_NVM_LOCK(server)` calls
`wh_Server_NvmLock(server)`, which acquires a mutex protecting NVM state. When
not threadsafe, the macros expand to `(WH_ERROR_OK)` (no-ops).

The existing (pre-branch) code unconditionally called `WH_SERVER_NVM_LOCK`
around every cert read/verify handler, because the cert always came from NVM.

### What changes for cached certs

Cached certs do not touch NVM at all — they are read from the in-memory key
cache via `wh_Server_KeystoreReadKey`. However, the NVM lock is still
unconditionally acquired around both cache and NVM paths. This is conservative
but correct: the key cache (`localCache` / `globalCache`) does not have its own
lock, so the NVM lock serves as the coarse serialization mechanism for all
server-side storage operations (both NVM and cache) when
`WOLFHSM_CFG_THREADSAFE` is enabled.

The pattern used in every updated handler is:

```c
rc = WH_SERVER_NVM_LOCK(server);
if (rc == WH_ERROR_OK) {
    if (req.id & WH_KEYID_CLIENT_WRAPPED_FLAG) {
        /* Cache path: translate and read from keystore cache */
        whKeyId certId = wh_KeyId_TranslateFromClient(
            WH_KEYTYPE_WRAPPED, server->comm->client_id, req.id);
        rc = wh_Server_KeystoreReadKey(server, certId, &meta, cert_data, &cert_len);
        /* ... exportability check for read-back requests ... */
    } else {
        /* NVM path (unchanged) */
        rc = wh_Nvm_GetMetadata(server->nvm, req.id, &meta);
        /* ... NVM reads ... */
    }
    (void)WH_SERVER_NVM_UNLOCK(server);
}
```

Key points:

- **Both paths hold the NVM lock**: The lock is always acquired before
  branching. While the cache read itself doesn't strictly need NVM protection,
  holding the lock ensures serialization with any concurrent operations that
  access the `localCache` array on other threads.

- **NVM path**: Unchanged — same behavior as before this branch.

### Backward compatibility

- All existing NVM-based certificate operations continue to work identically.
  The routing branch only activates when the key type is `WH_KEYTYPE_WRAPPED`.
- The `wh_Server_CertReadTrusted` and `wh_Server_CertVerify` function
  signatures changed from `whNvmId` to `whKeyId`. Since `whNvmId` and `whKeyId`
  are both `uint16_t`, this is ABI-compatible. Any existing callers passing a
  plain NVM ID (with TYPE=0) will hit the NVM path as before.
