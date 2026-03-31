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
 * wolfhsm/wh_server_object.h
 *
 */
#ifndef WOLFHSM_WH_SERVER_OBJECT_H_
#define WOLFHSM_WH_SERVER_OBJECT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_server.h"

/**
 * @brief Find a new unique object ID using the top bits of inout_id for user
 * and type
 *
 * Searches for an available object ID by checking against cache objects and NVM
 * storage. The client_id and type should be set by caller on inout_id.
 *
 * @param[in]     server    Server context
 * @param[in,out] inout_id  Input: object ID with type and user set; Output:
 * unique object ID
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectGetUniqueId(whServerContext* server, whNvmId* inout_id);

/**
 * @brief Find an available cache slot for the specified object size
 *
 * Searches for an empty slot or a slot with a committed object that can be
 * evicted. Returns the slot's buffer (zeroed) and metadata. Routes to the
 * appropriate cache (global or local) based on objId.
 *
 * @param[in]  server   Server context
 * @param[in]  objId    Object ID (used to route to correct cache)
 * @param[in]  objSz    Size of the object in bytes
 * @param[out] outBuf   Pointer to the cache buffer
 * @param[out] outMeta  Pointer to the metadata structure
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectGetCacheSlot(whServerContext* server, whKeyId objId,
                                 uint16_t objSz, uint8_t** outBuf,
                                 whNvmMetadata** outMeta);
int wh_Server_ObjectGetCacheSlotChecked(whServerContext* server,
                                        whKeyId objId, uint16_t objSz,
                                        uint8_t** outBuf,
                                        whNvmMetadata** outMeta);

/**
 * @brief Cache an object in server memory
 *
 * Stores an object in the appropriate cache (regular or big) based on its size.
 * Checks if the object is already committed to NVM.
 *
 * @param[in] server  Server context
 * @param[in] meta    Object metadata
 * @param[in] in      Object data buffer
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheAdd(whServerContext* server, whNvmMetadata* meta,
                             uint8_t* in);

/**
 * @brief Cache an object after enforcing object policy
 *
 * Runs policy checks (access/usage/etc.) before calling
 * wh_Server_ObjectCacheAdd.
 */
int wh_Server_ObjectCacheAddChecked(whServerContext* server,
                                    whNvmMetadata* meta, uint8_t* in);

/**
 * @brief Ensure an object is in cache, loading it from NVM if necessary
 *
 * Tries to put the specified object into cache if it isn't already there.
 * Returns pointers to the metadata and cached data.
 *
 * @param[in]  server   Server context
 * @param[in]  objId    Object ID to load
 * @param[out] outBuf   Pointer to the cached object buffer
 * @param[out] outMeta  Pointer to the object metadata
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheLoad(whServerContext* server, whKeyId objId,
                              uint8_t** outBuf, whNvmMetadata** outMeta);

/**
 * @brief Read an object from cache or NVM
 *
 * Retrieves an object from cache or NVM storage and returns its metadata and
 * data.
 *
 * @param[in]     server   Server context
 * @param[in]     objId    Object ID to read
 * @param[out]    outMeta  Object metadata (can be NULL)
 * @param[out]    out      Buffer to store object data (can be NULL)
 * @param[in,out] outSz    Input: size of out buffer; Output: actual object size
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheExport(whServerContext* server, whKeyId objId,
                                whNvmMetadata* outMeta, uint8_t* out,
                                uint32_t* outSz);

/**
 * @brief Read an object with policy enforcement
 *
 * Performs object policy checks before reading from cache/NVM.
 */
int wh_Server_ObjectCacheExportChecked(whServerContext* server, whKeyId objId,
                                       whNvmMetadata* outMeta, uint8_t* out,
                                       uint32_t* outSz);

/**
 * @brief Remove an object from cache
 *
 * Marks the object as erased in the cache if present.
 *
 * @param[in] server  Server context
 * @param[in] objId   Object ID to evict
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheEvict(whServerContext* server, whNvmId objId);

/**
 * @brief Evict an object with policy enforcement
 *
 * Checks policy before removing the object from cache.
 */
int wh_Server_ObjectCacheEvictChecked(whServerContext* server, whNvmId objId);

/**
 * @brief Commit a cached object to NVM storage
 *
 * Writes an object from cache to non-volatile memory and marks it as committed.
 * Fails with WH_ERROR_ACCESS if NONPERSISTABLE flag is set.
 *
 * @param[in] server  Server context
 * @param[in] objId   Object ID to commit
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheCommit(whServerContext* server, whNvmId objId);

/**
 * @brief Commit a cached object to NVM with policy enforcement
 *
 * Runs object policy checks before committing.
 */
int wh_Server_ObjectCacheCommitChecked(whServerContext* server, whNvmId objId);

/**
 * @brief Erase an object from both cache and NVM
 *
 * Removes the object from cache if present and destroys it in NVM.
 *
 * @param[in] server  Server context
 * @param[in] objId   Object ID to erase
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheErase(whServerContext* server, whNvmId objId);

/**
 * @brief Erase an object with policy enforcement
 *
 * Runs object policy checks before evicting/destroying.
 */
int wh_Server_ObjectCacheEraseChecked(whServerContext* server, whNvmId objId);

/**
 * @brief Revoke an object (clears usage and marks non-modifiable)
 *
 * Placeholder implementation for object revocation.
 */
int wh_Server_ObjectCacheRevoke(whServerContext* server, whKeyId objId);

/**
 * @brief Handle object management requests from clients
 *
 * Processes various object operations including cache, export, evict, commit,
 * and erase. Supports DMA operations if configured.
 *
 * @param[in]     server         Server context
 * @param[in]     magic          Message magic number
 * @param[in]     action         Object operation to perform
 * @param[in]     seq            Message sequence number
 * @param[in]     req_size       Size of request packet
 * @param[in]     req_packet     Request packet data
 * @param[out]    out_resp_size  Size of response packet
 * @param[out]    resp_packet    Response packet data
 * @return 0 on success, error code on failure
 */
int wh_Server_HandleObjectRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size,
                                  void* resp_packet);

/**
 * @brief Cache an object using DMA transfer
 *
 * Allocates a cache slot and copies object data from client memory using DMA.
 *
 * @param[in] server   Server context
 * @param[in] meta     Object metadata
 * @param[in] objAddr  Client memory address containing object data
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheAddDma(whServerContext* server, whNvmMetadata* meta,
                                uint64_t objAddr);

/**
 * @brief Cache an object with DMA after policy enforcement
 *
 * Performs policy checks before caching an object via DMA.
 */
int wh_Server_ObjectCacheAddDmaChecked(whServerContext* server,
                                       whNvmMetadata* meta, uint64_t objAddr);

/**
 * @brief Export an object using DMA transfer
 *
 * Copies object data from server cache to client memory using DMA.
 *
 * @param[in]  server   Server context
 * @param[in]  objId    Object ID to export
 * @param[in]  objAddr  Client memory address to receive object data
 * @param[in]  objSz    Size of client memory buffer
 * @param[out] outMeta  Buffer to receive object metadata
 * @return 0 on success, error code on failure
 */
int wh_Server_ObjectCacheExportDma(whServerContext* server, whKeyId objId,
                                   uint64_t objAddr, uint64_t objSz,
                                   whNvmMetadata* outMeta);

/**
 * @brief Export an object with DMA after policy enforcement
 *
 * Performs policy checks before exporting an object via DMA.
 */
int wh_Server_ObjectCacheExportDmaChecked(whServerContext* server,
                                          whKeyId objId, uint64_t objAddr,
                                          uint64_t objSz,
                                          whNvmMetadata* outMeta);

/**
 * @brief Enforce object usage policy given metadata
 *
 * Validates that an object has the required usage policy flags set in its
 * metadata. This is a pure policy check function that does not perform any
 * object lookups. Use this when you already have the object metadata available
 * to avoid duplicate object loading operations.
 *
 * @param[in] meta          Pointer to object metadata
 * @param[in] requiredUsage Required usage policy flags (e.g.,
 *                          WH_NVM_FLAGS_USAGE_ENCRYPT |
 * WH_NVM_FLAGS_USAGE_DECRYPT)
 * @return WH_ERROR_OK if the object has all required usage flags set
 * @return WH_ERROR_USAGE if the object does not have the required flags
 * @return WH_ERROR_BADARGS if meta is NULL
 */
int wh_Server_ObjectEnforceUsage(const whNvmMetadata* meta,
                                 whNvmFlags requiredUsage);

/**
 * Validates that an object has the required usage policy flags set
 *
 * This function enforces object usage policies by checking that the specified
 * object has all the required usage flags set in its metadata. It retrieves
 * the object metadata from the cache or NVM storage and performs a bitwise
 * check against the required flags.
 *
 * @param server Pointer to the server context
 * @param objId The translated server object ID (after client ID translation)
 * @param requiredUsage The required usage policy flags (e.g.,
 *                      WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT)
 *
 * @return WH_ERROR_OK if the object has all required usage flags set
 * @return WH_ERROR_USAGE if the object does not have the required flags
 * @return Other error codes if object metadata cannot be retrieved
 */
int wh_Server_ObjectFindEnforceUsage(whServerContext* server, whKeyId objId,
                                     whNvmFlags requiredUsage);

#endif /* !WOLFHSM_WH_SERVER_OBJECT_H_ */
