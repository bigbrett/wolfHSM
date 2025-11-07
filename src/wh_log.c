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
 * src/wh_log.c
 *
 * Generic logging frontend implementation
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"


int wh_Log_Init(whLogContext* ctx, const whLogConfig* config)
{
    int rc = 0;

    if ((ctx == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Backend doesn't support this operation */
    if (config->cb->Init == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    ctx->cb      = config->cb;
    ctx->context = config->context;

    rc = ctx->cb->Init(ctx->context, config->config);
    if (rc != WH_ERROR_OK) {
        /* Init failed, deinitialized context */
        ctx->cb      = NULL;
        ctx->context = NULL;
    }

    return rc;
}

int wh_Log_Cleanup(whLogContext* ctx)
{
    if ((ctx == NULL) || (ctx->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Cleanup == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Cleanup(ctx->context);
}

int wh_Log_AddEntry(whLogContext* ctx, const whLogEntry* entry)
{
    if ((ctx == NULL) || (ctx->cb == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->AddEntry == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->AddEntry(ctx->context, entry);
}

int wh_Log_Export(whLogContext* ctx, void* export_arg)
{
    if ((ctx == NULL) || (ctx->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Export == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Export(ctx->context, export_arg);
}

int wh_Log_Iterate(whLogContext* ctx, whLogIterateCb iterate_cb,
                   void* iterate_arg)
{
    if ((ctx == NULL) || (ctx->cb == NULL) || (iterate_cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Iterate == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Iterate(ctx->context, iterate_cb, iterate_arg);
}

int wh_Log_Clear(whLogContext* ctx)
{
    if ((ctx == NULL) || (ctx->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Clear == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Clear(ctx->context);
}
