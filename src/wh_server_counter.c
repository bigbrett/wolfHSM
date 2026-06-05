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
 * src/wh_server_counter.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER

#include <string.h>
#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_counter.h"
#include "wolfhsm/wh_server.h"

#include "wolfhsm/wh_server_counter.h"

int wh_Server_CounterInit(whServerContext* server, whNvmId counterId,
                          uint32_t* inout_counter)
{
    int           ret;
    whNvmMetadata meta[1] = {{0}};
    uint32_t*     counter = (uint32_t*)(&meta->label);

    if (server == NULL || server->comm == NULL || inout_counter == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* write the supplied value to nvm with the supplied id and client_id */
    meta->id =
        WH_MAKE_KEYID(WH_KEYTYPE_COUNTER, (uint16_t)server->comm->client_id,
                      (uint16_t)counterId);
    /* use the label buffer to hold the counter value */
    *counter = *inout_counter;

    ret = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, meta, 0, NULL);
        if (ret == WH_ERROR_OK) {
            *inout_counter = *counter;
        }
        (void)WH_SERVER_NVM_UNLOCK(server);
    } /* WH_SERVER_NVM_LOCK() */
    return ret;
}

int wh_Server_CounterIncrement(whServerContext* server, whNvmId counterId,
                               uint32_t* out_counter)
{
    int           ret;
    whNvmMetadata meta[1] = {{0}};
    uint32_t*     counter = (uint32_t*)(&meta->label);
    whKeyId       id;

    if (server == NULL || server->comm == NULL || out_counter == NULL) {
        return WH_ERROR_BADARGS;
    }

    id = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER, (uint16_t)server->comm->client_id,
                       (uint16_t)counterId);

    ret = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        /* read the counter, stored in the metadata label */
        ret = wh_Nvm_GetMetadata(server->nvm, id, meta);

        /* increment and write the counter back */
        if (ret == WH_ERROR_OK) {
            *counter = *counter + 1;
            /* set counter to uint32_t max if it rolled over */
            if (*counter == 0) {
                *counter = UINT32_MAX;
            }
            /* only update if we didn't saturate */
            else {
                ret = wh_Nvm_AddObjectWithReclaim(server->nvm, meta, 0, NULL);
            }
        }

        /* return counter to the caller */
        if (ret == WH_ERROR_OK) {
            *out_counter = *counter;
        }
        (void)WH_SERVER_NVM_UNLOCK(server);
    } /* WH_SERVER_NVM_LOCK() */
    return ret;
}

int wh_Server_CounterRead(whServerContext* server, whNvmId counterId,
                          uint32_t* out_counter)
{
    int           ret;
    whNvmMetadata meta[1] = {{0}};
    uint32_t*     counter = (uint32_t*)(&meta->label);
    whKeyId       id;

    if (server == NULL || server->comm == NULL || out_counter == NULL) {
        return WH_ERROR_BADARGS;
    }

    id = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER, (uint16_t)server->comm->client_id,
                       (uint16_t)counterId);

    ret = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        /* read the counter, stored in the metadata label */
        ret = wh_Nvm_GetMetadata(server->nvm, id, meta);

        /* return counter to the caller */
        if (ret == WH_ERROR_OK) {
            *out_counter = *counter;
        }
        (void)WH_SERVER_NVM_UNLOCK(server);
    } /* WH_SERVER_NVM_LOCK() */
    return ret;
}

int wh_Server_CounterDestroy(whServerContext* server, whNvmId counterId)
{
    int     ret;
    whKeyId id;

    if (server == NULL || server->comm == NULL) {
        return WH_ERROR_BADARGS;
    }

    id = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER, (uint16_t)server->comm->client_id,
                       (uint16_t)counterId);

    ret = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_DestroyObjects(server->nvm, 1, &id);
        (void)WH_SERVER_NVM_UNLOCK(server);
    } /* WH_SERVER_NVM_LOCK() */
    return ret;
}

int wh_Server_HandleCounter(whServerContext* server, uint16_t magic,
                            uint16_t action, uint16_t req_size,
                            const void* req_packet, uint16_t* out_resp_size,
                            void* resp_packet)
{
    int ret = 0;

    if (server == NULL || req_packet == NULL || out_resp_size == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_COUNTER_INIT: {
            whMessageCounter_InitRequest  req   = {0};
            whMessageCounter_InitResponse resp  = {0};
            uint32_t                      value = 0;

            if (req_size < sizeof(whMessageCounter_InitRequest)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                (void)wh_MessageCounter_TranslateInitRequest(
                    magic, (whMessageCounter_InitRequest*)req_packet, &req);
                value = req.counter;
                ret   = wh_Server_CounterInit(server, req.counterId, &value);
                if (ret == WH_ERROR_OK) {
                    resp.counter = value;
                }
                resp.rc = ret;
            }

            /* Always format a response, even on error: the dispatcher sends
             * this buffer back in-place regardless of our return code, so
             * skipping the format would echo the request bytes to the client
             * as a false success. */
            (void)wh_MessageCounter_TranslateInitResponse(
                magic, &resp, (whMessageCounter_InitResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_COUNTER_INCREMENT: {
            whMessageCounter_IncrementRequest  req  = {0};
            whMessageCounter_IncrementResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_IncrementRequest)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                (void)wh_MessageCounter_TranslateIncrementRequest(
                    magic, (whMessageCounter_IncrementRequest*)req_packet,
                    &req);
                ret     = wh_Server_CounterIncrement(server, req.counterId,
                                                     &resp.counter);
                resp.rc = ret;
            }

            (void)wh_MessageCounter_TranslateIncrementResponse(
                magic, &resp, (whMessageCounter_IncrementResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_COUNTER_READ: {
            whMessageCounter_ReadRequest  req  = {0};
            whMessageCounter_ReadResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_ReadRequest)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                (void)wh_MessageCounter_TranslateReadRequest(
                    magic, (whMessageCounter_ReadRequest*)req_packet, &req);
                ret =
                    wh_Server_CounterRead(server, req.counterId, &resp.counter);
                resp.rc = ret;
            }

            (void)wh_MessageCounter_TranslateReadResponse(
                magic, &resp, (whMessageCounter_ReadResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_COUNTER_DESTROY: {
            whMessageCounter_DestroyRequest  req  = {0};
            whMessageCounter_DestroyResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_DestroyRequest)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                (void)wh_MessageCounter_TranslateDestroyRequest(
                    magic, (whMessageCounter_DestroyRequest*)req_packet, &req);
                ret     = wh_Server_CounterDestroy(server, req.counterId);
                resp.rc = ret;
            }

            (void)wh_MessageCounter_TranslateDestroyResponse(
                magic, &resp, (whMessageCounter_DestroyResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        default:
            ret = WH_ERROR_BADARGS;
            break;
    }

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
