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
 * test/wh_test_log.c
 *
 * Unit tests for logging module
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wh_test_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"
#include "wolfhsm/wh_log_ringbuf.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h>
#include <unistd.h>
#include "port/posix/posix_log_file.h"
#endif

#include "wh_test_log.h"

#define ITERATE_STOP_MAGIC 99
#define ITERATE_STOP_COUNT 3


/* Mock log backend definitions */

#define MOCK_LOG_MAX_ENTRIES 16

typedef struct {
    whLogEntry entries[MOCK_LOG_MAX_ENTRIES];
    int        count;
    uint64_t   mock_time;
    int        init_called;
    int        cleanup_called;
} mockLogContext;

static int mockLog_Init(void* context, const void* config)
{
    mockLogContext* ctx = (mockLogContext*)context;
    (void)config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->init_called = 1;
    ctx->mock_time   = 1234567890000ULL; /* Fixed timestamp */
    return 0;
}

static int mockLog_Cleanup(void* context)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->cleanup_called = 1;
    return 0;
}

static int mockLog_AddEntry(void* context, const whLogEntry* entry)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL || entry == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->count >= MOCK_LOG_MAX_ENTRIES) {
        return WH_ERROR_NOSPACE;
    }

    memcpy(&ctx->entries[ctx->count], entry, sizeof(whLogEntry));
    ctx->count++;
    return 0;
}

/* Test-specific export structure for mock backend */
typedef struct {
    int (*callback)(void* arg, const whLogEntry* entry);
    void* callback_arg;
} mockLogExportArg;

static int mockLog_Export(void* context, void* export_arg)
{
    mockLogContext*   ctx  = (mockLogContext*)context;
    mockLogExportArg* args = (mockLogExportArg*)export_arg;
    int               i;
    int               ret;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* If no export args or callback, just succeed */
    if (args == NULL || args->callback == NULL) {
        return 0;
    }

    /* Iterate and call user's callback */
    for (i = 0; i < ctx->count; i++) {
        ret = args->callback(args->callback_arg, &ctx->entries[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int mockLog_Iterate(void* context, whLogIterateCb iterate_cb,
                           void* iterate_arg)
{
    mockLogContext* ctx = (mockLogContext*)context;
    int             i;
    int             ret;

    if (ctx == NULL || iterate_cb == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Iterate and call user's callback */
    for (i = 0; i < ctx->count; i++) {
        ret = iterate_cb(iterate_arg, &ctx->entries[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int mockLog_Clear(void* context)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->count = 0;
    memset(ctx->entries, 0, sizeof(ctx->entries));
    return 0;
}

static uint64_t mockLog_GetTime(void* context)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL) {
        return 0;
    }

    return ctx->mock_time++;
}

static whLogCb mockLogCb = {
    .Init     = mockLog_Init,
    .Cleanup  = mockLog_Cleanup,
    .AddEntry = mockLog_AddEntry,
    .Export   = mockLog_Export,
    .Iterate  = mockLog_Iterate,
    .Clear    = mockLog_Clear,
    .GetTime  = mockLog_GetTime,
};


/* Helper for iterate callback - counts entries */
static int iterateCallbackCount(void* arg, const whLogEntry* entry)
{
    int* count = (int*)arg;
    (void)entry;
    (*count)++;
    return 0;
}

/* Helper callback - stops iteration after 2 entries */
static int iterateCallbackStopAt2(void* arg, const whLogEntry* entry)
{
    int* count = (int*)arg;
    (void)entry;
    (*count)++;
    if (*count >= ITERATE_STOP_COUNT) {
        /* Custom return code to test propagation */
        return ITERATE_STOP_MAGIC;
    }
    return WH_ERROR_OK;
}

/* Helper for iterate callback - validates specific entries */
typedef struct {
    int count;
    int valid; /* Set to 0 if entry doesn't match expected pattern */
} iterateValidationArgs;

static int iterateCallbackValidator(void* arg, const whLogEntry* entry)
{
    iterateValidationArgs* args = (iterateValidationArgs*)arg;
    char                   expected[32];

    /* Expect messages like "Entry 0", "Entry 1", etc. */
    snprintf(expected, sizeof(expected), "Entry %d", args->count);

    if (strcmp(entry->msg, expected) != 0) {
        args->valid = 0;
    }
    if (entry->level != WH_LOG_LEVEL_INFO) {
        args->valid = 0;
    }

    args->count++;
    return 0;
}

/* Frontend API test using mock backend */
static int whTest_LogFrontend(void)
{
    whLogContext          logCtx;
    mockLogContext        mockCtx;
    whLogConfig           logConfig;
    int                   iterate_count = 0;
    int                   i;
    mockLogExportArg      exportArgs;
    iterateValidationArgs valArgs;
    whLogEntry            entry = {0};

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&mockCtx, 0, sizeof(mockCtx));
    logConfig.cb      = &mockLogCb;
    logConfig.context = &mockCtx;
    logConfig.config  = NULL;

    /* Test: NULL input rejections */
    WH_TEST_ASSERT_RETURN(wh_Log_Init(NULL, &logConfig) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Init(&logCtx, NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_AddEntry(NULL, &entry) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_AddEntry(&logCtx, NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Cleanup(NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Clear(NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Export(NULL, &exportArgs) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Iterate(NULL, iterateCallbackCount,
                                         &iterate_count) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Iterate(&logCtx, NULL, &iterate_count) ==
                          WH_ERROR_BADARGS);

    /* Initialize the log context */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(mockCtx.init_called == 1);

    /* Test: Fill buffer completely and verify all entries */
    for (i = 0; i < MOCK_LOG_MAX_ENTRIES; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Entry %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }
    WH_TEST_ASSERT_RETURN(mockCtx.count == MOCK_LOG_MAX_ENTRIES);

    /* Verify each entry has correct content */
    for (i = 0; i < MOCK_LOG_MAX_ENTRIES; i++) {
        char expected[32];
        snprintf(expected, sizeof(expected), "Entry %d", i);
        WH_TEST_ASSERT_RETURN(strcmp(mockCtx.entries[i].msg, expected) == 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].level == WH_LOG_LEVEL_INFO);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].file != NULL);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].function != NULL);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].line > 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].timestamp > 0);
    }

    /* Test: Export works */
    iterate_count           = 0;
    exportArgs.callback     = iterateCallbackCount;
    exportArgs.callback_arg = &iterate_count;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, &exportArgs));
    WH_TEST_ASSERT_RETURN(iterate_count == MOCK_LOG_MAX_ENTRIES);

    /* Test: Iterate works and iterates over expected elements */
    valArgs.count = 0;
    valArgs.valid = 1;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackValidator, &valArgs));
    WH_TEST_ASSERT_RETURN(valArgs.count == MOCK_LOG_MAX_ENTRIES);
    WH_TEST_ASSERT_RETURN(valArgs.valid == 1);

    /* Test: Clear works */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_TEST_ASSERT_RETURN(mockCtx.count == 0);

    /* Verify buffer is actually empty via iterate */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    /* Test: Can write after clear */
    WH_LOG_INFO(&logCtx, "Entry 0");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 1);
    WH_TEST_ASSERT_RETURN(strcmp(mockCtx.entries[0].msg, "Entry 0") == 0);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    WH_TEST_ASSERT_RETURN(mockCtx.cleanup_called == 1);

    return 0;
}

/* Test helper macros using mock backend */
static int whTest_LogMacros(void)
{
    whLogContext   logCtx;
    mockLogContext mockCtx;
    whLogConfig    logConfig;

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&mockCtx, 0, sizeof(mockCtx));
    logConfig.cb      = &mockLogCb;
    logConfig.context = &mockCtx;
    logConfig.config  = NULL;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: WH_LOG_INFO creates proper entry with __FILE__/__LINE__ */
    WH_LOG_INFO(&logCtx, "Info message");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 1);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].level == WH_LOG_LEVEL_INFO);
    WH_TEST_ASSERT_RETURN(strcmp(mockCtx.entries[0].msg, "Info message") == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].file != NULL);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].function != NULL);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].line > 0);

    /* Test: WH_LOG_ERROR creates proper entry */
    WH_LOG_ERROR(&logCtx, "Error message");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 2);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strcmp(mockCtx.entries[1].msg, "Error message") == 0);

    /* Test: WH_LOG_SECEVENT creates proper entry */
    WH_LOG_SECEVENT(&logCtx, "Security event");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 3);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[2].level == WH_LOG_LEVEL_SECEVENT);
    WH_TEST_ASSERT_RETURN(strcmp(mockCtx.entries[2].msg, "Security event") ==
                          0);

    /* Test: Timestamp is populated from GetTime callback */
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].timestamp >= 1234567890000ULL);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].timestamp >
                          mockCtx.entries[0].timestamp);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    return 0;
}


/*
 * Generic backend test - smoke test for basic operations
 */
static int whTest_LogBackend_BasicOperations(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup log configuration */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;

    /* Test: Init with valid config */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Add single entry */
    WH_LOG_INFO(&logCtx, "Single entry");
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 1);

    /* Test: Add multiple entries (3) */
    WH_LOG_INFO(&logCtx, "Entry 0");
    WH_LOG_INFO(&logCtx, "Entry 1");
    WH_LOG_INFO(&logCtx, "Entry 2");

    /* Verify count via Iterate */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 4); /* 1 + 3 */

    /* Test: Clear and verify empty */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    /* Test: Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    return WH_ERROR_OK;
}

/*
 * Generic backend test - Capacity Handling
 * Tests behavior when buffer reaches capacity
 */
static int whTest_LogBackend_CapacityHandling(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;
    int          i;

    /* Skip if capacity is unlimited */
    if (cfg->expected_capacity < 0) {
        printf("    Skipped (unlimited capacity)\n");
        return WH_ERROR_OK;
    }

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup and init */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Fill to capacity */
    for (i = 0; i < cfg->expected_capacity; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Entry %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    /* Verify count == capacity */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == cfg->expected_capacity);

    /* Test: Add 10 more entries (overflow) */
    for (i = 0; i < 10; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Overflow %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    /* Verify count still == capacity (overflow behavior) */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == cfg->expected_capacity);

    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    return WH_ERROR_OK;
}

/*
 * Generic backend test - Message Handling
 * Tests various message sizes and special characters
 */
static int whTest_LogBackend_MessageHandling(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;
    whLogEntry   entry;
    char         maxMsg[WOLFHSM_CFG_LOG_MSG_MAX];

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup and init */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Empty message */
    WH_LOG_INFO(&logCtx, "");

    /* Test: Short message */
    WH_LOG_INFO(&logCtx, "Hi");

    /* Test: Max size message (255 chars + null) */
    memset(maxMsg, 'A', sizeof(maxMsg) - 1);
    maxMsg[sizeof(maxMsg) - 1] = '\0';
    memset(&entry, 0, sizeof(entry));
    entry.timestamp = cfg->cb->GetTime ? cfg->cb->GetTime(backend_context) : 0;
    entry.level     = WH_LOG_LEVEL_INFO;
    entry.file      = __FILE__;
    entry.function  = __func__;
    entry.line      = __LINE__;
    entry.msg_len   = strlen(maxMsg);
    memcpy(entry.msg, maxMsg, entry.msg_len);
    entry.msg[entry.msg_len] = '\0';
    WH_TEST_RETURN_ON_FAIL(wh_Log_AddEntry(&logCtx, &entry));


    /* Verify all entries were added */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    return WH_ERROR_OK;
}

/*
 * Generic backend test - Iteration
 * Tests iteration behavior in various scenarios
 */
static int whTest_LogBackend_Iteration(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;
    int          ret;

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup and init */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Clear first to ensure clean state for persistent backends */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));

    /* Test: Iterate empty log */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    /* Test: Iterate single entry */
    WH_LOG_INFO(&logCtx, "Single");
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 1);

    /* Test: Iterate 3 entries */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_LOG_INFO(&logCtx, "Entry 1");
    WH_LOG_INFO(&logCtx, "Entry 2");
    WH_LOG_INFO(&logCtx, "Entry 3");
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    /* Test: Early termination (callback returns magic number after
     * fixed number of entries) */
    iterate_count = 0;
    ret = wh_Log_Iterate(&logCtx, iterateCallbackStopAt2, &iterate_count);
    WH_TEST_ASSERT_RETURN(ret == ITERATE_STOP_MAGIC);
    WH_TEST_ASSERT_RETURN(iterate_count == ITERATE_STOP_COUNT);

    /* Test: Iterate after clear */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    return WH_ERROR_OK;
}

/*
 * Generic backend tests - Main runner
 * Executes all generic backend tests on a given backend test config
 */
int whTest_LogBackend_RunAll(whTestLogBackendTestConfig* cfg)
{
    int ret = 0;

    /* Call setup hook if provided */
    if (cfg->setup != NULL) {
        if (cfg->setup(&cfg->test_context) != 0) {
            printf("ERROR: Setup hook failed\n");
            return WH_TEST_FAIL;
        }
    }

    /* Run all test suites */
    ret = whTest_LogBackend_BasicOperations(cfg);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("whTest_LogBackend_BasicOperations returned %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = whTest_LogBackend_CapacityHandling(cfg);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("whTest_LogBackend_CapacityHandling returned %d\n",
                           ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = whTest_LogBackend_MessageHandling(cfg);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("whTest_LogBackend_MessageHandling returned %d\n",
                           ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = whTest_LogBackend_Iteration(cfg);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("whTest_LogBackend_Iteration returned %d\n", ret);
        }
    }

    /* Call teardown hook if provided */
    if (cfg->teardown != NULL) {
        if (cfg->teardown(cfg->test_context) != 0) {
            WH_ERROR_PRINT("Teardown hook failed\n");
            return WH_TEST_FAIL;
        }
    }

    return ret;
}


/* Simple GetTime function for ring buffer tests */
static uint64_t ringbufTestGetTime(void* context)
{
    static uint64_t counter = 5000000000000ULL;
    (void)context; /* Unused */
    return counter++;
}

/* Ring buffer backend tests */
static int whTest_LogRingbuf(void)
{
    whLogContext        logCtx;
    whLogRingbufContext ringbufCtx;
    whLogRingbufConfig  ringbufConfig;
    whLogConfig         logConfig;
    int                 i;
    int                 iterate_count;
    uint32_t            capacity;
    /* Backend storage for ring buffer */
    const size_t numLogEntries = 32;
    whLogEntry   ringbuf_buffer[numLogEntries];

    /* Setup ring buffer backend */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&ringbufCtx, 0, sizeof(ringbufCtx));
    memset(&ringbuf_buffer, 0, sizeof(ringbuf_buffer));

    /* Configure ring buffer with user-supplied buffer */
    ringbufConfig.buffer      = ringbuf_buffer;
    ringbufConfig.buffer_size = sizeof(ringbuf_buffer);

    /* Initialize callback table */
    whLogCb ringbufCb = WH_LOG_RINGBUF_CB;
    ringbufCb.GetTime = ringbufTestGetTime;

    logConfig.cb      = &ringbufCb;
    logConfig.context = &ringbufCtx;
    logConfig.config  = &ringbufConfig;

    /* Test: Init with valid config */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(ringbufCtx.initialized == 1);
    WH_TEST_ASSERT_RETURN(ringbufCtx.head == 0);
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 0);

    /* Get capacity from initialized context */
    capacity = ringbufCtx.capacity;
    WH_TEST_ASSERT_RETURN(capacity == numLogEntries);

    /* Test: Add a few entries */
    for (i = 0; i < 5; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Message %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 5);
    WH_TEST_ASSERT_RETURN(ringbufCtx.head == 5);

    /* Verify the entries are correct */
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 5);
    WH_TEST_ASSERT_RETURN(ringbufCtx.head == 5);
    for (i = 0; i < 5; i++) {
        char expected[32];
        snprintf(expected, sizeof(expected), "Message %d", i);
        WH_TEST_ASSERT_RETURN(strcmp(ringbufCtx.entries[i].msg, expected) == 0);
    }

    /* Test: Clear buffer */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 0);
    WH_TEST_ASSERT_RETURN(ringbufCtx.head == 0);

    /* Test: Fill buffer to capacity */
    for (i = 0; i < (int)capacity; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Entry %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    WH_TEST_ASSERT_RETURN(ringbufCtx.count == capacity);
    WH_TEST_ASSERT_RETURN(ringbufCtx.head == 0); /* Wrapped around */

    /* Test: Wraparound - add more entries to overwrite oldest */
    for (i = 0; i < 5; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Wrapped %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    /* Count should still be at capacity */
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == capacity);
    WH_TEST_ASSERT_RETURN(ringbufCtx.head == 5); /* 5 entries past wrap */

    /* Verify oldest entries were overwritten */
    WH_TEST_ASSERT_RETURN(strcmp(ringbufCtx.entries[0].msg, "Wrapped 0") == 0);
    WH_TEST_ASSERT_RETURN(strcmp(ringbufCtx.entries[4].msg, "Wrapped 4") == 0);

    /* Verify some non-overwritten entries still exist */
    WH_TEST_ASSERT_RETURN(strncmp(ringbufCtx.entries[5].msg, "Entry ", 6) == 0);

    /* Test: Iterate through ring buffer */
    /* Clear and add known entries for iteration test */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    for (i = 0; i < 3; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Iterate test %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    /* Count entries via iteration */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    /* Test: Iterate when buffer is full and wrapped */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    for (i = 0; i < (int)capacity + 5; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Wrap %d", i);
        WH_LOG_INFO(&logCtx, msg);
    }

    /* Should iterate exactly capacity entries */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == (int)capacity);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    WH_TEST_ASSERT_RETURN(ringbufCtx.initialized == 0);

    return 0;
}

#if defined(WOLFHSM_CFG_TEST_POSIX)

/* POSIX file backend tests */
static int whTest_LogPosixFile(void)
{
    whLogContext        logCtx;
    posixLogFileContext posixCtx;
    posixLogFileConfig  posixCfg;
    whLogConfig         logConfig;
    whLogCb             posixCb       = POSIX_LOG_FILE_CB;
    const char*         test_log_file = "/tmp/wolfhsm_test_log.txt";
    int                 export_count;
    int                 iterate_count;

    /* Remove any existing test log file */
    unlink(test_log_file);

    /* Test: Create log file, add entries, verify file exists */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&posixCtx, 0, sizeof(posixCtx));
    posixCfg.filename = test_log_file;

    logConfig.cb      = &posixCb;
    logConfig.context = &posixCtx;
    logConfig.config  = &posixCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(posixCtx.initialized == 1);
    WH_TEST_ASSERT_RETURN(posixCtx.fd >= 0);

    /* Add some log entries */
    WH_LOG_INFO(&logCtx, "First info message");
    WH_LOG_ERROR(&logCtx, "First error message");
    WH_LOG_SECEVENT(&logCtx, "First security event");

    /* Test: Export reads back all entries correctly */
    /* For POSIX backend, export to a temp file and count lines */
    FILE* export_fp = fopen("/tmp/wolfhsm_export_verify.txt", "w");
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, export_fp));
    fclose(export_fp);

    /* Count lines in exported file */
    export_fp = fopen("/tmp/wolfhsm_export_verify.txt", "r");
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    export_count = 0;
    char line[2048];
    while (fgets(line, sizeof(line), export_fp) != NULL) {
        export_count++;
    }
    fclose(export_fp);
    unlink("/tmp/wolfhsm_export_verify.txt");
    WH_TEST_ASSERT_RETURN(export_count == 3);

    /* Test: Append preserves existing entries */
    WH_LOG_INFO(&logCtx, "Second info message");
    export_fp = fopen("/tmp/wolfhsm_export_verify.txt", "w");
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, export_fp));
    fclose(export_fp);
    export_fp    = fopen("/tmp/wolfhsm_export_verify.txt", "r");
    export_count = 0;
    while (fgets(line, sizeof(line), export_fp) != NULL) {
        export_count++;
    }
    fclose(export_fp);
    unlink("/tmp/wolfhsm_export_verify.txt");
    WH_TEST_ASSERT_RETURN(export_count == 4);

    /* Test: Clear truncates file */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    export_fp = fopen("/tmp/wolfhsm_export_verify.txt", "w");
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, export_fp));
    fclose(export_fp);
    export_fp    = fopen("/tmp/wolfhsm_export_verify.txt", "r");
    export_count = 0;
    while (fgets(line, sizeof(line), export_fp) != NULL) {
        export_count++;
    }
    fclose(export_fp);
    unlink("/tmp/wolfhsm_export_verify.txt");
    WH_TEST_ASSERT_RETURN(export_count == 0);

    /* Test: Iterate functionality with parsing */
    /* Add entries for iterate test */
    WH_LOG_INFO(&logCtx, "Iterate message 1");
    WH_LOG_ERROR(&logCtx, "Iterate message 2");
    WH_LOG_SECEVENT(&logCtx, "Iterate message 3");

    /* Count entries via iteration */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    /* Remove test log file */
    unlink(test_log_file);

    return 0;
}

/* Thread function for concurrent access test */
typedef struct {
    whLogContext* ctx;
    int           thread_id;
    int           iterations;
} thread_test_args;

static void* threadTestFunc(void* arg)
{
    thread_test_args* args = (thread_test_args*)arg;
    int               i;
    char              msg[64];

    for (i = 0; i < args->iterations; i++) {
        snprintf(msg, sizeof(msg), "Thread %d iteration %d", args->thread_id,
                 i);
        /* Can't use WH_LOG_INFO macro with dynamic string, so create entry
         * manually */
        whLogEntry entry;
        memset(&entry, 0, sizeof(entry));
        entry.timestamp = posixLogFile_GetTime(NULL);
        entry.level     = WH_LOG_LEVEL_INFO;
        entry.file      = __FILE__;
        entry.function  = __func__;
        entry.line      = __LINE__;
        entry.msg_len   = strlen(msg);
        if (entry.msg_len >= WOLFHSM_CFG_LOG_MSG_MAX) {
            entry.msg_len = WOLFHSM_CFG_LOG_MSG_MAX - 1;
        }
        memcpy(entry.msg, msg, entry.msg_len);
        entry.msg[entry.msg_len] = '\0';

        if (wh_Log_AddEntry(args->ctx, &entry) != 0) {
            return (void*)-1;
        }
    }

    return (void*)0;
}

static int whTest_LogPosixFileConcurrent(void)
{
    whLogContext        logCtx;
    posixLogFileContext posixCtx;
    posixLogFileConfig  posixCfg;
    whLogConfig         logConfig;
    whLogCb             posixCb       = POSIX_LOG_FILE_CB;
    const char*         test_log_file = "/tmp/wolfhsm_test_log_concurrent.txt";
    int                 export_count;
    const int           NUM_THREADS           = 4;
    const int           ITERATIONS_PER_THREAD = 10;
    pthread_t           threads[4];
    thread_test_args    args[4];
    int                 i;

    /* Remove any existing test log file */
    unlink(test_log_file);

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&posixCtx, 0, sizeof(posixCtx));
    posixCfg.filename = test_log_file;

    logConfig.cb      = &posixCb;
    logConfig.context = &posixCtx;
    logConfig.config  = &posixCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Concurrent access from multiple threads */
    for (i = 0; i < NUM_THREADS; i++) {
        args[i].ctx        = &logCtx;
        args[i].thread_id  = i;
        args[i].iterations = ITERATIONS_PER_THREAD;

        if (pthread_create(&threads[i], NULL, threadTestFunc, &args[i]) != 0) {
            WH_ERROR_PRINT("Failed to create thread %d\n", i);
            return WH_TEST_FAIL;
        }
    }

    /* Wait for all threads */
    for (i = 0; i < NUM_THREADS; i++) {
        void* result;
        pthread_join(threads[i], &result);
        if (result != (void*)0) {
            WH_ERROR_PRINT("Thread %d failed\n", i);
            return WH_TEST_FAIL;
        }
    }

    /* Verify all entries were written */
    /* For POSIX backend, export to a temp file and count lines */
    FILE* verify_fp = fopen("/tmp/wolfhsm_export_verify_concurrent.txt", "w");
    WH_TEST_ASSERT_RETURN(verify_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, verify_fp));
    fclose(verify_fp);

    /* Count lines in exported file */
    verify_fp = fopen("/tmp/wolfhsm_export_verify_concurrent.txt", "r");
    WH_TEST_ASSERT_RETURN(verify_fp != NULL);
    export_count = 0;
    char line[2048];
    while (fgets(line, sizeof(line), verify_fp) != NULL) {
        export_count++;
    }
    fclose(verify_fp);
    unlink("/tmp/wolfhsm_export_verify_concurrent.txt");
    WH_TEST_ASSERT_RETURN(export_count == NUM_THREADS * ITERATIONS_PER_THREAD);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    /* Remove test log file */
    unlink(test_log_file);

    return 0;
}

#endif /* WOLFHSM_CFG_TEST_POSIX */

/* Generic backend tests using test harness */

/* Mock backend generic tests */
static int whTest_LogMock_Generic(void)
{
    mockLogContext             mockCtx;
    whTestLogBackendTestConfig testCfg;

    memset(&mockCtx, 0, sizeof(mockCtx));

    testCfg.backend_name        = "Mock";
    testCfg.cb                  = &mockLogCb;
    testCfg.config              = NULL;
    testCfg.config_size         = sizeof(mockLogContext);
    testCfg.backend_context     = &mockCtx;
    testCfg.expected_capacity   = MOCK_LOG_MAX_ENTRIES;
    testCfg.supports_concurrent = 0;
    testCfg.setup               = NULL;
    testCfg.teardown            = NULL;
    testCfg.test_context        = NULL;

    return whTest_LogBackend_RunAll(&testCfg);
}

/* Ring buffer backend generic tests */
static int whTest_LogRingbuf_Generic(void)
{
    whLogRingbufContext        ringbufCtx;
    whLogRingbufConfig         ringbufConfig;
    whTestLogBackendTestConfig testCfg;
    whLogCb                    ringbufCb;
    const size_t               numLogEntries = 32;
    static whLogEntry          ringbuf_buffer[32];

    /* Setup ring buffer configuration with user-supplied buffer */
    memset(&ringbuf_buffer, 0, sizeof(ringbuf_buffer));
    memset(&ringbufCtx, 0, sizeof(ringbufCtx));
    ringbufConfig.buffer      = ringbuf_buffer;
    ringbufConfig.buffer_size = sizeof(ringbuf_buffer);

    /* Initialize callback table with GetTime function (C90 compatible) */
    memset(&ringbufCb, 0, sizeof(ringbufCb));
    ringbufCb.Init     = whLogRingbuf_Init;
    ringbufCb.Cleanup  = whLogRingbuf_Cleanup;
    ringbufCb.AddEntry = whLogRingbuf_AddEntry;
    ringbufCb.Export   = whLogRingbuf_Export;
    ringbufCb.Iterate  = whLogRingbuf_Iterate;
    ringbufCb.Clear    = whLogRingbuf_Clear;
    ringbufCb.GetTime  = ringbufTestGetTime;

    testCfg.backend_name        = "RingBuffer";
    testCfg.cb                  = &ringbufCb;
    testCfg.config              = &ringbufConfig;
    testCfg.config_size         = sizeof(whLogRingbufContext);
    testCfg.backend_context     = &ringbufCtx;
    testCfg.expected_capacity   = numLogEntries;
    testCfg.supports_concurrent = 0;
    testCfg.setup               = NULL;
    testCfg.teardown            = NULL;
    testCfg.test_context        = NULL;

    return whTest_LogBackend_RunAll(&testCfg);
}

#if defined(WOLFHSM_CFG_TEST_POSIX)
/* POSIX file backend generic tests */
static int whTest_LogPosixFile_Generic(void)
{
    posixLogFileContext        posixCtx;
    posixLogFileConfig         posixCfg;
    whTestLogBackendTestConfig testCfg;
    whLogCb                    posixCb;
    const char*                test_log_file = "/tmp/wolfhsm_test_generic.log";

    /* Initialize callback table (C90 compatible) */
    memset(&posixCtx, 0, sizeof(posixCtx));
    memset(&posixCb, 0, sizeof(posixCb));
    posixCb.Init     = posixLogFile_Init;
    posixCb.Cleanup  = posixLogFile_Cleanup;
    posixCb.AddEntry = posixLogFile_AddEntry;
    posixCb.Export   = posixLogFile_Export;
    posixCb.Iterate  = posixLogFile_Iterate;
    posixCb.Clear    = posixLogFile_Clear;
    posixCb.GetTime  = posixLogFile_GetTime;

    /* Remove any existing test log file */
    unlink(test_log_file);

    posixCfg.filename = test_log_file;

    testCfg.backend_name        = "PosixFile";
    testCfg.cb                  = &posixCb;
    testCfg.config              = &posixCfg;
    testCfg.config_size         = sizeof(posixLogFileContext);
    testCfg.backend_context     = &posixCtx;
    testCfg.expected_capacity   = -1; /* Unlimited */
    testCfg.supports_concurrent = 1;
    testCfg.setup               = NULL;
    testCfg.teardown            = NULL;
    testCfg.test_context        = NULL;

    return whTest_LogBackend_RunAll(&testCfg);
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

/* Main test entry point */
int whTest_Log(void)
{
    printf("Testing log frontend API...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogFrontend());

    printf("Testing log macros...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogMacros());

    printf("Running Generic Backend Tests...\n");
    printf("Testing mock log backend in generic harness...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogMock_Generic());
    printf("Testing ringbuf backend in generic harness...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogRingbuf_Generic());
#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing posix file backend in generic harness...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogPosixFile_Generic());
#endif

    printf("Running Backend-Specific Tests... n");
    printf("Testing ring buffer backend...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogRingbuf());

#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing POSIX file backend...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogPosixFile());

    printf("Testing POSIX file backend with concurrent access...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogPosixFileConcurrent());
#endif

    printf("Log tests PASSED\n");

    return WH_ERROR_OK;
}
