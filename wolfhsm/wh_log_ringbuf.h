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
 * wolfhsm/wh_log_ringbuf.h
 *
 * Ring buffer logging backend with fixed capacity in RAM. Simple, portable,
 * and not thread-safe. Overwrites oldest entries when full.
 */

#ifndef WOLFHSM_WH_LOG_RINGBUF_H_
#define WOLFHSM_WH_LOG_RINGBUF_H_

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_log.h"

#include <stdint.h>

/* Ring buffer context structure */
typedef struct whLogRingbufContext_t {
    whLogEntry entries[WOLFHSM_CFG_LOG_RINGBUF_SIZE]; /* Fixed-size buffer */
    uint32_t   head;        /* Next write position (0 to capacity-1) */
    uint32_t   count;       /* Current entries (0 to capacity) */
    int        initialized; /* Initialization flag */
} whLogRingbufContext;

/* Callback functions */
int whLogRingbuf_Init(void* context, const void* config);
int whLogRingbuf_Cleanup(void* context);
int whLogRingbuf_AddEntry(void* context, const whLogEntry* entry);
int whLogRingbuf_Export(void* context, void* export_arg);
int whLogRingbuf_Clear(void* context);

/* Convenience macro for callback table initialization.
 * Note: User must provide their own GetTime function when using this backend.
 * Example usage:
 *   whLogCb cb = WH_LOG_RINGBUF_CB;
 *   cb.GetTime = myGetTimeFunction;
 */
/* clang-format off */
#define WH_LOG_RINGBUF_CB                                                     \
    {                                                                         \
        .Init = whLogRingbuf_Init,                                            \
        .Cleanup = whLogRingbuf_Cleanup,                                      \
        .AddEntry = whLogRingbuf_AddEntry,                                    \
        .Export = whLogRingbuf_Export,                                        \
        .Clear = whLogRingbuf_Clear,                                          \
        .GetTime = NULL,                                                      \
    }
/* clang-format on */

#endif /* !WOLFHSM_WH_LOG_RINGBUF_H_ */
