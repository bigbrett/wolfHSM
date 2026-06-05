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
 * wolfhsm/wh_server_counter.h
 *
 */

#ifndef WOLFHSM_WH_SERVER_COUNTER_H_
#define WOLFHSM_WH_SERVER_COUNTER_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_server.h"

int wh_Server_HandleCounter(whServerContext* server, uint16_t magic,
                            uint16_t action, uint16_t req_size,
                            const void* req_packet, uint16_t* out_resp_size,
                            void* resp_packet);

/*
 * Counter operations. Each scopes counterId to the calling client
 * (server->comm->client_id). Counters are NVM-only (no cache), so with no NVM
 * attached these return an error rather than crashing. These are the
 * server-side counterparts to the wh_Client_Counter* API and are what
 * wh_Server_HandleCounter dispatches to.
 */

/**
 * @brief Create/reset a counter to a given value.
 * @param[in] server Server context.
 * @param[in] counterId Client-scoped counter id.
 * @param[in,out] inout_counter In: initial value. Out: value stored by the HSM.
 * @return WH_ERROR_OK on success or a negative error code.
 */
int wh_Server_CounterInit(whServerContext* server, whNvmId counterId,
                          uint32_t* inout_counter);

/**
 * @brief Increment a counter (saturating at UINT32_MAX) and return its value.
 * @param[in] server Server context.
 * @param[in] counterId Client-scoped counter id.
 * @param[out] out_counter Resulting counter value.
 * @return WH_ERROR_OK on success or a negative error code.
 */
int wh_Server_CounterIncrement(whServerContext* server, whNvmId counterId,
                               uint32_t* out_counter);

/**
 * @brief Read a counter's current value.
 * @param[in] server Server context.
 * @param[in] counterId Client-scoped counter id.
 * @param[out] out_counter Current counter value.
 * @return WH_ERROR_OK on success or a negative error code.
 */
int wh_Server_CounterRead(whServerContext* server, whNvmId counterId,
                          uint32_t* out_counter);

/**
 * @brief Destroy a counter.
 * @param[in] server Server context.
 * @param[in] counterId Client-scoped counter id.
 * @return WH_ERROR_OK on success or a negative error code.
 */
int wh_Server_CounterDestroy(whServerContext* server, whNvmId counterId);

#endif /* !WOLFHSM_WH_SERVER_COUNTER_H_ */
