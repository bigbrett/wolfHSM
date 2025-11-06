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

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h>
#include <unistd.h>
#include "port/posix/posix_log_file.h"
#endif

#include "wh_test_log.h"

/* Mock backend for frontend API testing */
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
    .Clear    = mockLog_Clear,
    .GetTime  = mockLog_GetTime,
};

/* Helper for export callback */
static int exportCallbackHelper(void* arg, const whLogEntry* entry)
{
    int* count = (int*)arg;
    (void)entry;
    (*count)++;
    return 0;
}

/* Frontend API tests */
static int whTest_LogFrontend(void)
{
    whLogContext   logCtx;
    mockLogContext mockCtx;
    whLogConfig    logConfig;
    whLogEntry     entry;
    int            export_count = 0;

    /* Test: Init with valid config */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&mockCtx, 0, sizeof(mockCtx));
    logConfig.cb      = &mockLogCb;
    logConfig.context = &mockCtx;
    logConfig.config  = NULL;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(mockCtx.init_called == 1);
    WH_TEST_ASSERT_RETURN(logCtx.cb == &mockLogCb);
    WH_TEST_ASSERT_RETURN(logCtx.context == &mockCtx);

    /* Test: Init with NULL context (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_Init(NULL, &logConfig) == WH_ERROR_BADARGS);

    /* Test: Init with NULL config (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_Init(&logCtx, NULL) == WH_ERROR_BADARGS);

    /* Test: AddEntry with valid entry */
    memset(&entry, 0, sizeof(entry));
    entry.timestamp = 1234567890000ULL;
    entry.level     = WH_LOG_LEVEL_INFO;
    entry.file      = __FILE__;
    entry.function  = __func__;
    entry.line      = __LINE__;
    entry.msg_len   = 11;
    memcpy(entry.msg, "Test message", 12);

    WH_TEST_RETURN_ON_FAIL(wh_Log_AddEntry(&logCtx, &entry));
    WH_TEST_ASSERT_RETURN(mockCtx.count == 1);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].level == WH_LOG_LEVEL_INFO);
    WH_TEST_ASSERT_RETURN(strcmp(mockCtx.entries[0].msg, "Test message") == 0);

    /* Test: AddEntry with NULL context (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_AddEntry(NULL, &entry) == WH_ERROR_BADARGS);

    /* Test: AddEntry with NULL entry (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_AddEntry(&logCtx, NULL) == WH_ERROR_BADARGS);

    /* Test: Export with callback validation */
    export_count = 0;
    mockLogExportArg exportArgs = {.callback     = exportCallbackHelper,
                                   .callback_arg = &export_count};
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, &exportArgs));
    WH_TEST_ASSERT_RETURN(export_count == 1);

    /* Test: Export with NULL context (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_Export(NULL, &exportArgs) == WH_ERROR_BADARGS);

    /* Test: Export with NULL arg (should succeed but do nothing) */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, NULL));

    /* Test: Clear operation */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_TEST_ASSERT_RETURN(mockCtx.count == 0);

    /* Test: Clear with NULL context (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_Clear(NULL) == WH_ERROR_BADARGS);

    /* Test: Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    WH_TEST_ASSERT_RETURN(mockCtx.cleanup_called == 1);

    /* Test: Cleanup with NULL context (expect WH_ERROR_BADARGS) */
    WH_TEST_ASSERT_RETURN(wh_Log_Cleanup(NULL) == WH_ERROR_BADARGS);

    return 0;
}

/* Macro tests */
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

/* Main test entry point */
int whTest_Log(void)
{
    printf("Testing log frontend API...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogFrontend());
    printf("Log frontend API tests passed\n");

    printf("Testing log macros...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogMacros());
    printf("Log macro tests passed\n");

#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing POSIX file backend...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogPosixFile());
    printf("POSIX file backend tests passed\n");

    printf("Testing POSIX file backend with concurrent access...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogPosixFileConcurrent());
    printf("POSIX file backend concurrent tests passed\n");
#endif

    return 0;
}
