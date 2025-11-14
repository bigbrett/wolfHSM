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

/** Backend provides timestamp via callback */
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

/** Helper macros
 *
 * WH_LOG:     for string literals (compile-time known size)
 * WH_LOG_STR: for runtime C strings (char*)
 *
 * Both silently truncate to WOLFHSM_CFG_LOG_MSG_MAX - 1 and always
 * null-terminate the stored message.
 */
/* clang-format off */
#define WH_LOG(ctx, lvl, message)                                              \
    do {                                                                       \
        uint64_t _timestamp =                                                  \
            (((ctx) != NULL) && (ctx)->cb && (ctx)->cb->GetTime)               \
                ? (ctx)->cb->GetTime((ctx)->context)                           \
                : 0;                                                           \
        size_t _src_len = sizeof(message) - 1;                                 \
        size_t _max_len =                                                      \
            (WOLFHSM_CFG_LOG_MSG_MAX > 0) ? (WOLFHSM_CFG_LOG_MSG_MAX - 1) : 0; \
        size_t     _copy_len = (_src_len < _max_len) ? _src_len : _max_len;    \
        whLogEntry _entry    = {.timestamp = _timestamp,                       \
                                .level     = (lvl),                            \
                                .file      = __FILE__,                         \
                                .function  = __func__,                         \
                                .line      = __LINE__,                         \
                                .msg_len   = (uint32_t)_copy_len};             \
        if (_copy_len > 0) {                                                   \
            memcpy(_entry.msg, (message), _copy_len);                          \
        }                                                                      \
        _entry.msg[_copy_len] = '\0';                                          \
        wh_Log_AddEntry((ctx), &_entry);                                       \
    } while (0)

#define WH_LOG_STR(ctx, lvl, cstr)                                             \
    do {                                                                       \
        uint64_t _timestamp =                                                  \
            (((ctx) != NULL) && (ctx)->cb && (ctx)->cb->GetTime)               \
                ? (ctx)->cb->GetTime((ctx)->context)                           \
                : 0;                                                           \
        const char* _s = (const char*)(cstr);                                  \
        size_t      _max_len =                                                 \
            (WOLFHSM_CFG_LOG_MSG_MAX > 0) ? (WOLFHSM_CFG_LOG_MSG_MAX - 1) : 0; \
        size_t _copy_len = 0;                                                  \
        if (_s != NULL) {                                                      \
            size_t _i;                                                         \
            for (_i = 0; _i < _max_len; _i++) {                                \
                if (_s[_i] == '\0') {                                          \
                    break;                                                     \
                }                                                              \
            }                                                                  \
            _copy_len = _i;                                                    \
        }                                                                      \
        whLogEntry _entry = {.timestamp = _timestamp,                          \
                             .level     = (lvl),                               \
                             .file      = __FILE__,                            \
                             .function  = __func__,                            \
                             .line      = __LINE__,                            \
                             .msg_len   = (uint32_t)_copy_len};                \
        if ((_s != NULL) && (_copy_len > 0)) {                                 \
            memcpy(_entry.msg, _s, _copy_len);                                 \
        }                                                                      \
        _entry.msg[_copy_len] = '\0';                                          \
        wh_Log_AddEntry((ctx), &_entry);                                       \
    } while (0)
/* clang-format on */

#define WH_LOG_INFO(ctx, msg) WH_LOG(ctx, WH_LOG_LEVEL_INFO, msg)
#define WH_LOG_ERROR(ctx, msg) WH_LOG(ctx, WH_LOG_LEVEL_ERROR, msg)
#define WH_LOG_SECEVENT(ctx, msg) WH_LOG(ctx, WH_LOG_LEVEL_SECEVENT, msg)

#define WH_LOG_INFO_STR(ctx, s) WH_LOG_STR(ctx, WH_LOG_LEVEL_INFO, (s))
#define WH_LOG_ERROR_STR(ctx, s) WH_LOG_STR(ctx, WH_LOG_LEVEL_ERROR, (s))
#define WH_LOG_SECEVENT_STR(ctx, s) WH_LOG_STR(ctx, WH_LOG_LEVEL_SECEVENT, (s))

#endif /* WOLFHSM_WH_LOG_H_ */
