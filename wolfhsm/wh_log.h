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
 * wolfhsm/wh_log.h
 *
 * Generic logging frontend API with callback backend interface
 */

#ifndef WOLFHSM_WH_LOG_H_
#define WOLFHSM_WH_LOG_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include <stdint.h>
#include <string.h>

/** Log levels */
typedef enum {
    WH_LOG_LEVEL_INFO     = 0, /* Informational message */
    WH_LOG_LEVEL_ERROR    = 1, /* Error message */
    WH_LOG_LEVEL_SECEVENT = 2  /* Security event */
} whLogLevel;

/** Backend provides timestamp via callback (no system clock dependency in
 * frontend) */
typedef uint64_t (*whLogGetTimeCb)(void* context);

/** Log entry structure with fixed-size message buffer */
typedef struct {
    uint64_t    timestamp;             /* Unix timestamp (milliseconds) */
    whLogLevel  level;                 /* Log level */
    const char* file;                  /* Source file (__FILE__) */
    const char* function;              /* Function name (__func__) */
    uint32_t    line;                  /* Line number (__LINE__) */
    uint32_t    msg_len;               /* Actual message length (excluding
                                        * null terminator) */
    char msg[WOLFHSM_CFG_LOG_MSG_MAX]; /* Fixed buffer with null
                                        * terminator */
} whLogEntry;

/** User-provided callback for iterating log entries.
 * Return 0 to continue iteration, non-zero to stop early. */
typedef int (*whLogIterateCb)(void* arg, const whLogEntry* entry);

/** Backend callback interface */
typedef struct {
    int (*Init)(void* context, const void* config);
    int (*Cleanup)(void* context);
    int (*AddEntry)(void* context, const whLogEntry* entry);
    int (*Export)(void* context, void* export_arg);
    int (*Iterate)(void* context, whLogIterateCb iterate_cb, void* iterate_arg);
    int (*Clear)(void* context);
    whLogGetTimeCb GetTime; /* Required: backend provides time */
} whLogCb;

/** Frontend context */
typedef struct {
    whLogCb* cb;      /* Callback table */
    void*    context; /* Opaque backend context */
} whLogContext;

/** Frontend configuration */
typedef struct {
    whLogCb* cb;      /* Callback table */
    void*    context; /* Pre-allocated backend context */
    void*    config;  /* Backend-specific config */
} whLogConfig;

/** Frontend API */
int wh_Log_Init(whLogContext* ctx, const whLogConfig* config);
int wh_Log_Cleanup(whLogContext* ctx);
int wh_Log_AddEntry(whLogContext* ctx, const whLogEntry* entry);
int wh_Log_Export(whLogContext* ctx, void* export_arg);
int wh_Log_Iterate(whLogContext* ctx, whLogIterateCb iterate_cb,
                   void* iterate_arg);
int wh_Log_Clear(whLogContext* ctx);

/** Helper macros with static assert for compile-time message size validation
 */
/* Static assert for C11+ or C++, runtime check for C90/C99 */
#if (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)) || \
    (defined(__cplusplus) && (__cplusplus >= 201103L))
#define WH_LOG(ctx, lvl, message)                                        \
    do {                                                                 \
        WH_UTILS_STATIC_ASSERT(                                          \
            sizeof(message) <= WOLFHSM_CFG_LOG_MSG_MAX,                  \
            "WH_LOG: message exceeds WOLFHSM_CFG_LOG_MSG_MAX");          \
        uint64_t   _timestamp = ((ctx)->cb && (ctx)->cb->GetTime)        \
                                    ? (ctx)->cb->GetTime((ctx)->context) \
                                    : 0;                                 \
        size_t     _len       = sizeof(message) - 1;                     \
        whLogEntry _entry     = {.timestamp = _timestamp,                \
                                 .level     = (lvl),                     \
                                 .file      = __FILE__,                  \
                                 .function  = __func__,                  \
                                 .line      = __LINE__,                  \
                                 .msg_len   = _len};                       \
        memcpy(_entry.msg, message, sizeof(message));                    \
        wh_Log_AddEntry((ctx), &_entry);                                 \
    } while (0)
#else
/* C90/C99: Skip static assert to avoid unused typedef warnings */
#define WH_LOG(ctx, lvl, message)                                        \
    do {                                                                 \
        uint64_t   _timestamp = ((ctx)->cb && (ctx)->cb->GetTime)        \
                                    ? (ctx)->cb->GetTime((ctx)->context) \
                                    : 0;                                 \
        size_t     _len       = sizeof(message) - 1;                     \
        whLogEntry _entry     = {.timestamp = _timestamp,                \
                                 .level     = (lvl),                     \
                                 .file      = __FILE__,                  \
                                 .function  = __func__,                  \
                                 .line      = __LINE__,                  \
                                 .msg_len   = _len};                       \
        if (sizeof(message) > WOLFHSM_CFG_LOG_MSG_MAX) {                 \
            _len = WOLFHSM_CFG_LOG_MSG_MAX - 1;                          \
        }                                                                \
        memcpy(_entry.msg, message, _len + 1);                           \
        wh_Log_AddEntry((ctx), &_entry);                                 \
    } while (0)
#endif

#define WH_LOG_INFO(ctx, msg) WH_LOG(ctx, WH_LOG_LEVEL_INFO, msg)
#define WH_LOG_ERROR(ctx, msg) WH_LOG(ctx, WH_LOG_LEVEL_ERROR, msg)
#define WH_LOG_SECEVENT(ctx, msg) WH_LOG(ctx, WH_LOG_LEVEL_SECEVENT, msg)

#endif /* !WOLFHSM_WH_LOG_H_ */
