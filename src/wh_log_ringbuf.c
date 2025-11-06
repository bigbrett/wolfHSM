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
 * src/wh_log_ringbuf.c
 *
 * Ring buffer logging backend implementation
 */

#include <stddef.h> /* For NULL */
#include <string.h> /* For memset, memcpy */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"
#include "wolfhsm/wh_log_ringbuf.h"

int whLogRingbuf_Init(void* c, const void* cf)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;

    /* Config not used */
    (void)cf;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize context */
    memset(context, 0, sizeof(*context));
    context->head        = 0;
    context->count       = 0;
    context->initialized = 1;

    return WH_ERROR_OK;
}

int whLogRingbuf_Cleanup(void* c)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->initialized) {
        (void)whLogRingbuf_Clear(context);
        context->initialized = 0;
    }

    return WH_ERROR_OK;
}

int whLogRingbuf_AddEntry(void* c, const whLogEntry* entry)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;
    uint32_t             capacity;

    if ((context == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized) {
        return WH_ERROR_ABORTED;
    }

    capacity = WOLFHSM_CFG_LOG_RINGBUF_SIZE;

    /* Copy entry to ring buffer at head position */
    memcpy(&context->entries[context->head], entry, sizeof(whLogEntry));

    /* Advance head with wraparound */
    context->head = (context->head + 1) % capacity;

    /* Increment count, capped at capacity */
    if (context->count < capacity) {
        context->count++;
    }

    return WH_ERROR_OK;
}

int whLogRingbuf_Export(void* c, void* export_arg)
{
    (void)c;
    (void)export_arg;
    return WH_ERROR_OK;
}

int whLogRingbuf_Clear(void* c)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Reset ring buffer state */
    context->head  = 0;
    context->count = 0;

    /* Zero the log entries */
    memset(context->entries, 0, sizeof(context->entries));

    return WH_ERROR_OK;
}
