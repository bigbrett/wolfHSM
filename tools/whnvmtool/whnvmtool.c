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
 * tools/whnvmtool/whnvmtool.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/stat.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "port/posix/posix_flash_file.h"
#include "port/posix/posix_transport_tcp.h"

/* Key entries embed clientId in the 4-bit USER field and keyId in the 8-bit
 * ID field of the 16-bit NVM id; larger values would silently alias other
 * ids (clientId 16 would even land in the global namespace), so reject them
 * at parse time. Raw NVM objects use the full 16-bit id space. */
#define MAX_CLIENT_ID 15
#define MAX_KEY_ENTRY_ID 0xFF
#define MAX_OBJ_ID UINT16_MAX

/* SHE entries have a 4-bit slot number, a 28-bit update counter, and the five
 * WH_SHE_FLAG_* protection bits. SHE keys are raw 16-byte AES/CMAC keys.
 * Slot 14 (RAM_KEY) is volatile per the SHE spec and never NVM-backed, so
 * provisioning it is rejected. */
#define MAX_SHE_SLOT 15
#define SHE_RAM_KEY_SLOT 14
#define MAX_SHE_COUNTER 0x0FFFFFFF
#define MAX_SHE_FLAGS 0x1F
#define SHE_KEY_SIZE 16

/* Macros for maximum file path length (Linux PATH_MAX is a good reference) */
#define MAX_FILE_PATH_LENGTH PATH_MAX

/* Parameterize MAX_LINE_LENGTH by 512 bytes + MAX_FILE_PATH_LENGTH */
#define MAX_LINE_LENGTH (512 + MAX_FILE_PATH_LENGTH)

#define INTERMEDIATE_FILE "nvm_metadata.txt"
#define DEFAULT_IMAGE_FILE "whNvmImage.bin"
#define DEFAULT_HEX_FILE "whNvmImage.hex"
#define DEFAULT_PARTITION_SIZE 0x10000
#define DEFAULT_ERASED_BYTE 0xFF

/* Data bytes per intel hex record */
#define HEX_RECORD_DATA_LEN 16

/* Config entry kind, from the line's leading token */
typedef enum EntryType {
    ENTRY_TYPE_OBJ = 0,
    ENTRY_TYPE_KEY,
    ENTRY_TYPE_SHE
} EntryType;

/* Structure representing an entry in the linked list */
typedef struct Entry {
    EntryType type;           /* obj, key, or she */
    uint8_t   clientId;       /* Used only for keys and SHE slots */
    uint16_t  id;             /* Object ID for NVM, keyId for keys, slot
                               * number for SHE */
    uint16_t      access;     /* Access permissions (obj and key only) */
    uint16_t      flags;      /* Flags for the object (obj and key only) */
    uint32_t      sheCounter; /* SHE update counter (she only) */
    uint32_t      sheFlags;   /* SHE protection flags (she only) */
    char*         label;      /* Label for the object (obj and key only) */
    char*         filePath;   /* File path for the object */
    struct Entry* next;       /* Pointer to the next entry */
} Entry;

/* Head of the linked list for entries */
Entry* entryHead = NULL;

/* Flash callback wrapper that records which image bytes get programmed. The
 * hex output must emit only programmed bytes and skip everything still
 * erased, and the final image contents alone cannot show the difference:
 * programmed data may legitimately contain the erased value. */
typedef struct {
    posixFlashFileContext posixCtx; /* must be first: the untracked posix
                                     * callbacks receive this context */
    uint8_t* written; /* one flag per image byte, 1 = programmed. NULL
                       * disables tracking. Sized to the full image, the
                       * same bound the posix layer checks offsets against */
} TrackedFlashContext;

/* clang-format off */
#define TRACKED_FLASH_CB                                \
    {                                                   \
        .Init          = posixFlashFile_Init,           \
        .Cleanup       = posixFlashFile_Cleanup,        \
        .PartitionSize = posixFlashFile_PartitionSize,  \
        .WriteLock     = posixFlashFile_WriteLock,      \
        .WriteUnlock   = posixFlashFile_WriteUnlock,    \
        .Read          = posixFlashFile_Read,           \
        .Program       = trackedFlashProgram,           \
        .Erase         = trackedFlashErase,             \
        .Verify        = posixFlashFile_Verify,         \
        .BlankCheck    = posixFlashFile_BlankCheck,     \
    }
/* clang-format on */

/* Flag to indicate if we're in test mode, set by --test command line argument.
 * If set, write the metadata ID/filepath pair to an intermediate file so the
 * test code can parse this file and associate object IDs with their input data
 * to verify the results against known good data */
static int gTestMode = 0;


/* Function prototypes */
static void   writeMetadataToFile(uint32_t metadataId, const char* filePath);
static int    initializeServer(whServerContext*      serverContext,
                               whNvmContext*         nvmContext,
                               const whServerConfig* serverConfig,
                               const whNvmConfig*    nvmConfig);
static void   cleanupServer(whServerContext* serverContext);
static Entry* createEntry(EntryType type, uint8_t clientId, uint16_t id,
                          uint16_t access, uint16_t flags, uint32_t sheCounter,
                          uint32_t sheFlags, const char* label,
                          const char* filePath);
static void   appendEntry(Entry** head, EntryType type, uint8_t clientId,
                          uint16_t id, uint16_t access, uint16_t flags,
                          uint32_t sheCounter, uint32_t sheFlags,
                          const char* label, const char* filePath);
static int    processEntry(Entry* entry, whNvmContext* nvmContext);
static int    processEntries(whNvmContext* nvmContext);
static void   freeEntries(void);
static void   stripComment(char* line);
static void   trimWhitespace(char* str);
static int  parseInteger(const char* str, uint32_t maxValue, uint32_t* result);
static int    parseUint32(const char* str, uint32_t* result);
static void parseConfigFile(const char* filePath);
static int    trackedFlashProgram(void* c, uint32_t offset, uint32_t size,
                                  const uint8_t* data);
static int    trackedFlashErase(void* c, uint32_t offset, uint32_t size);
static int    writeHexRecord(FILE* file, uint8_t type, uint16_t addr,
                             const uint8_t* data, uint8_t len);
static int    writeHexRange(FILE* file, const uint8_t* image, uint32_t baseAddr,
                            uint32_t start, uint32_t end, uint16_t* upper);
static int    writeHexFile(const char* hexPath, const char* imagePath,
                           const uint8_t* written, uint32_t imageSize,
                           uint32_t baseAddr, uint32_t align);
static void   printUsage(const char* progName);


/* Creates a new entry in the linked list based on the provided parameters */
Entry* createEntry(EntryType type, uint8_t clientId, uint16_t id,
                   uint16_t access, uint16_t flags, uint32_t sheCounter,
                   uint32_t sheFlags, const char* label, const char* filePath)
{
    Entry* newEntry = (Entry*)malloc(sizeof(Entry));
    if (!newEntry) {
        fprintf(stderr, "Memory allocation error\n");
        exit(EXIT_FAILURE);
    }
    newEntry->type       = type;
    newEntry->clientId   = clientId;
    newEntry->id         = id;
    newEntry->access     = access;
    newEntry->flags      = flags;
    newEntry->sheCounter = sheCounter;
    newEntry->sheFlags   = sheFlags;
    newEntry->label      = strdup(label);
    newEntry->filePath   = strdup(filePath);
    newEntry->next       = NULL;
    return newEntry;
}

/* Appends a new entry to the linked list */
void appendEntry(Entry** head, EntryType type, uint8_t clientId, uint16_t id,
                 uint16_t access, uint16_t flags, uint32_t sheCounter,
                 uint32_t sheFlags, const char* label, const char* filePath)
{
    Entry* newEntry = createEntry(type, clientId, id, access, flags, sheCounter,
                                  sheFlags, label, filePath);
    if (*head == NULL) {
        *head = newEntry;
    }
    else {
        Entry* current = *head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = newEntry;
    }
}

/* Writes a list entry to NVM and optionally to an intermediate file for
 * test mode. Returns 0 on success, -1 if the entry was not added */
static int processEntry(Entry* entry, whNvmContext* nvmContext)
{
    FILE* file = fopen(entry->filePath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s\n", entry->filePath);
        return -1;
    }

    /* Get the file size */
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* NVM object lengths are 16-bit, so larger files would silently
     * truncate. Negative means ftell failed */
    if ((fileSize < 0) || (fileSize > (long)UINT16_MAX)) {
        fprintf(stderr, "Error: Invalid size %ld for file %s (max %u bytes)\n",
                fileSize, entry->filePath, (unsigned)UINT16_MAX);
        fclose(file);
        return -1;
    }

    /* Allocate memory for the file data */
    uint8_t* buffer = (uint8_t*)malloc(fileSize);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for file %s\n",
                entry->filePath);
        fclose(file);
        return -1;
    }

    /* Read the file data into the buffer */
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    fclose(file);

    if (bytesRead != fileSize) {
        fprintf(stderr, "Error: Failed to read entire file %s\n",
                entry->filePath);
        free(buffer);
        return -1;
    }

    if ((entry->type == ENTRY_TYPE_SHE) && (fileSize != SHE_KEY_SIZE)) {
        fprintf(stderr, "Error: SHE key file %s must be %d bytes, got %ld\n",
                entry->filePath, SHE_KEY_SIZE, fileSize);
        free(buffer);
        return -1;
    }

    /* Create metadata for the new entry */
    whNvmMetadata meta  = {0};
    uint32_t      tmp32 = 0;
    switch (entry->type) {
        case ENTRY_TYPE_KEY:
            /* Keys have special ID format */
            meta.id =
                WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, entry->clientId, entry->id);
            WOLFHSM_CFG_PRINTF(
                "Processing Key Entry - ClientID: 0x%X, KeyID: 0x%X, Meta ID: "
                "0x%X, "
                "Access: 0x%X, Flags: 0x%X, Label: %s, File: %s, Size: %ld\n",
                entry->clientId, entry->id, meta.id, entry->access,
                entry->flags, entry->label, entry->filePath, fileSize);
            break;
        case ENTRY_TYPE_SHE:
            meta.id = WH_MAKE_KEYID(WH_KEYTYPE_SHE, entry->clientId, entry->id);
            WOLFHSM_CFG_PRINTF(
                "Processing SHE Entry - ClientID: 0x%X, Slot: 0x%X, Meta ID: "
                "0x%X, "
                "Counter: 0x%X, Flags: 0x%X, File: %s, Size: %ld\n",
                entry->clientId, entry->id, meta.id, entry->sheCounter,
                entry->sheFlags, entry->filePath, fileSize);
            break;
        case ENTRY_TYPE_OBJ:
        default:
            meta.id = entry->id;
            WOLFHSM_CFG_PRINTF("Processing Object Entry - ID: 0x%X, Access: "
                               "0x%X, Flags: 0x%X, "
                               "Label: %s, File: %s, Size: %ld\n",
                               entry->id, entry->access, entry->flags,
                               entry->label, entry->filePath, fileSize);
            break;
    }
    meta.access = entry->access;
    meta.flags  = entry->flags;
    meta.len    = fileSize;
    if (entry->type == ENTRY_TYPE_SHE) {
        /* First 8 label bytes hold the update counter and protection flags
         * as big-endian words, matching wh_She_Meta2Label() */
        tmp32 = wh_Utils_htonl(entry->sheCounter);
        memcpy(meta.label, &tmp32, sizeof(tmp32));
        tmp32 = wh_Utils_htonl(entry->sheFlags);
        memcpy(meta.label + sizeof(tmp32), &tmp32, sizeof(tmp32));
    }
    else {
        snprintf((char*)meta.label, WH_NVM_LABEL_LEN, "%s", entry->label);
    }

    int rc = wh_Nvm_AddObject(nvmContext, &meta, fileSize, buffer);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to add entry ID %u to NVM, ret = %d\n",
                meta.id, rc);
        free(buffer);
        return -1;
    }

    if (gTestMode) {
        writeMetadataToFile(meta.id, entry->filePath);
    }

    free(buffer);
    return 0;
}

/* Iterates through the linked list and processes each entry, stopping at
 * the first failure. Returns 0 if all entries were added, -1 otherwise */
static int processEntries(whNvmContext* nvmContext)
{
    Entry* current = entryHead;
    while (current != NULL) {
        if (processEntry(current, nvmContext) != 0) {
            return -1;
        }
        current = current->next;
    }
    return 0;
}

/* Frees the memory allocated for the linked list */
void freeEntries()
{
    Entry* current = entryHead;
    while (current != NULL) {
        Entry* next = current->next;
        free(current->label);
        free(current->filePath);
        free(current);
        current = next;
    }
}

/* Function to remove comments from a line */
void stripComment(char* line)
{
    char* commentStart = strchr(line, '#');
    if (commentStart) {
        /* Null-terminate the line at the start of the comment */
        *commentStart = '\0';
    }
}

/* Function to trim leading and trailing whitespace */
void trimWhitespace(char* str)
{
    /* Trim leading whitespace */
    char* start = str;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    /* Trim trailing whitespace */
    char* end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    /* Copy the trimmed string back into the original buffer */
    memmove(str, start, strlen(start) + 1);
}

/* Function to parse a uint16_t or uint8_t from a string (handles hex or
 * decimal) */
int parseInteger(const char* str, uint32_t maxValue, uint32_t* result)
{
    char* endPtr;
    long  value;

    if (strstr(str, "0x") == str) {
        /* Parse as hexadecimal */
        value = strtol(str, &endPtr, 16);
    }
    else {
        /* Parse as decimal */
        value = strtol(str, &endPtr, 10);
    }

    if (*endPtr != '\0' || value < 0 || value > maxValue) {
        return 0; /* Error: invalid number */
    }

    *result = (uint32_t)value;
    return 1; /* Success */
}

/* Parse a full-range 32-bit unsigned integer from a string (handles hex or
 * decimal). Returns 0 on success, -1 on error */
int parseUint32(const char* str, uint32_t* result)
{
    char*         endPtr = NULL;
    unsigned long value;

    if (!isdigit((unsigned char)str[0])) {
        return -1; /* strtoul accepts leading whitespace and signs */
    }

    errno = 0;
    if (strstr(str, "0x") == str) {
        value = strtoul(str, &endPtr, 16);
    }
    else {
        value = strtoul(str, &endPtr, 10);
    }

    if ((endPtr == str) || (*endPtr != '\0') || (errno != 0) ||
        (value > 0xFFFFFFFFUL)) {
        return -1;
    }

    *result = (uint32_t)value;
    return 0;
}

/* Function to parse the configuration file and build the linked list */
void parseConfigFile(const char* filePath)
{
    FILE* file = fopen(filePath, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    int  lineNumber = 0;

    while (fgets(line, sizeof(line), file)) {
        lineNumber++;
        stripComment(line);
        trimWhitespace(line);

        /* Skip empty lines after removing comments and whitespace */
        if (strlen(line) == 0) {
            continue;
        }

        char*     token;
        char      label[256] = "";
        char      filePath[MAX_FILE_PATH_LENGTH];
        uint32_t  clientId = 0, id, access = 0, flags = 0;
        uint32_t  sheCounter = 0, sheFlags = 0;
        EntryType entryType;

        /* Check if the line defines a key, a SHE key, or an object */
        if (strncmp(line, "key", 3) == 0) {
            entryType = ENTRY_TYPE_KEY;

            /* Parse client ID for key entries */
            token = strtok(line + 3, " ");
            if (!token || !parseInteger(token, MAX_CLIENT_ID, &clientId)) {
                fprintf(stderr,
                        "Error on line %d: Malformed key entry - invalid "
                        "clientId\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse key ID for key entries; 0 (WH_KEYID_ERASED) is invalid */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, MAX_KEY_ENTRY_ID, &id) ||
                (id == 0)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed key entry - invalid keyId\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else if (strncmp(line, "she", 3) == 0) {
            entryType = ENTRY_TYPE_SHE;

            /* Parse client ID for SHE entries (0 = global namespace) */
            token = strtok(line + 3, " ");
            if (!token || !parseInteger(token, MAX_CLIENT_ID, &clientId)) {
                fprintf(stderr,
                        "Error on line %d: Malformed she entry - invalid "
                        "clientId\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse SHE slot number */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, MAX_SHE_SLOT, &id)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed she entry - invalid slot\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* A provisioned RAM_KEY would wrongly persist across reboot and
             * shadow runtime loads after cache eviction */
            if (id == SHE_RAM_KEY_SLOT) {
                fprintf(stderr,
                        "Error on line %d: she slot 14 (RAM_KEY) is volatile "
                        "and cannot be provisioned\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse SHE update counter */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, MAX_SHE_COUNTER, &sheCounter)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed she entry - invalid counter\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse SHE protection flags */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, MAX_SHE_FLAGS, &sheFlags)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed she entry - invalid flags\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else if (strncmp(line, "obj", 3) == 0) {
            entryType = ENTRY_TYPE_OBJ;

            /* Parse object ID for object entries; 0 (WH_NVM_ID_INVALID) is
             * invalid */
            token = strtok(line + 3, " ");
            if (!token || !parseInteger(token, MAX_OBJ_ID, &id) || (id == 0)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed object entry - invalid id\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else {
            /* Report error for unknown entry types */
            fprintf(stderr,
                    "Error on line %d: Malformed line or unknown entry type\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* SHE entries have no access, flags, or label fields; their label is
         * built from the counter and protection flags instead */
        if (entryType != ENTRY_TYPE_SHE) {
            /* Parse access field */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, UINT16_MAX, &access)) {
                fprintf(stderr,
                        "Error on line %d: Malformed entry - invalid access\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse flags */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, UINT16_MAX, &flags)) {
                fprintf(stderr,
                        "Error on line %d: Malformed entry - invalid flags\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse the label (enclosed in quotes) */
            token = strtok(NULL, "\"");
            if (!token) {
                fprintf(stderr,
                        "Error on line %d: Malformed entry - missing or "
                        "incorrect label format\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
            snprintf(label, sizeof(label), "%s", token);
        }

        /* Parse the file path */
        token = strtok(NULL, " ");
        if (!token) {
            fprintf(stderr,
                    "Error on line %d: Malformed entry - missing file path\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }
        if (snprintf(filePath, sizeof(filePath), "%s", token) >=
            (int)sizeof(filePath)) {
            fprintf(stderr, "Error on line %d: File path too long\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Add the parsed entry to the linked list */
        appendEntry(&entryHead, entryType, (uint8_t)clientId, (uint16_t)id,
                    (uint16_t)access, (uint16_t)flags, sheCounter, sheFlags,
                    label, filePath);
    }

    fclose(file);
}

/* Writes the metadata ID and filepath to an intermediate file for test mode.
 *  The format of the file should be comma separated <metadata ID>,<file path>
 * pairs, with one entry per line */
static void writeMetadataToFile(uint32_t metadataId, const char* filePath)
{
    FILE* file = fopen(INTERMEDIATE_FILE, "a");
    if (file == NULL) {
        fprintf(stderr,
                "Error: Unable to open intermediate file for writing\n");
        return;
    }

    char fullPath[PATH_MAX];
    if (realpath(filePath, fullPath) == NULL) {
        fprintf(stderr, "Error: Unable to get full path for %s\n", filePath);
        fclose(file);
        return;
    }

    fprintf(file, "%u,%s\n", metadataId, fullPath);
    fclose(file);
}

/* Program passthrough that marks the programmed bytes in the tracking map */
static int trackedFlashProgram(void* c, uint32_t offset, uint32_t size,
                               const uint8_t* data)
{
    TrackedFlashContext* ctx = c;
    int rc = posixFlashFile_Program(&ctx->posixCtx, offset, size, data);
    /* Success means the posix layer bounds-checked offset and size */
    if ((rc == 0) && (ctx->written != NULL) && (data != NULL) && (size > 0)) {
        memset(&ctx->written[offset], 1, size);
    }
    return rc;
}

/* Erase passthrough that clears the erased bytes in the tracking map */
static int trackedFlashErase(void* c, uint32_t offset, uint32_t size)
{
    TrackedFlashContext* ctx = c;
    int rc = posixFlashFile_Erase(&ctx->posixCtx, offset, size);
    if ((rc == 0) && (ctx->written != NULL) && (size > 0)) {
        memset(&ctx->written[offset], 0, size);
    }
    return rc;
}

/* Write a single intel hex record with its checksum */
static int writeHexRecord(FILE* file, uint8_t type, uint16_t addr,
                          const uint8_t* data, uint8_t len)
{
    uint8_t sum;
    int     i;

    sum = (uint8_t)(len + (addr >> 8) + (addr & 0xFF) + type);
    if (fprintf(file, ":%02X%04X%02X", len, addr, type) < 0) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        if (fprintf(file, "%02X", data[i]) < 0) {
            return -1;
        }
        sum = (uint8_t)(sum + data[i]);
    }
    if (fprintf(file, "%02X\n", (uint8_t)(0x100 - sum)) < 0) {
        return -1;
    }
    return 0;
}

/* Write data records for image bytes [start, end), inserting extended linear
 * address records whenever the upper 16 address bits change. *upper holds the
 * current upper bits between calls and starts at 0, the intel hex default */
static int writeHexRange(FILE* file, const uint8_t* image, uint32_t baseAddr,
                         uint32_t start, uint32_t end, uint16_t* upper)
{
    while (start < end) {
        uint32_t addr     = baseAddr + start;
        uint16_t addrHigh = (uint16_t)(addr >> 16);
        uint32_t chunk    = HEX_RECORD_DATA_LEN;

        if (chunk > (end - start)) {
            chunk = end - start;
        }
        /* Records must not cross a 64KB address boundary */
        if (chunk > (0x10000UL - (addr & 0xFFFFUL))) {
            chunk = 0x10000UL - (addr & 0xFFFFUL);
        }

        if (addrHigh != *upper) {
            uint8_t upperData[2];
            upperData[0] = (uint8_t)(addrHigh >> 8);
            upperData[1] = (uint8_t)(addrHigh & 0xFF);
            if (writeHexRecord(file, 4, 0, upperData, 2) != 0) {
                return -1;
            }
            *upper = addrHigh;
        }

        if (writeHexRecord(file, 0, (uint16_t)(addr & 0xFFFF), &image[start],
                           (uint8_t)chunk) != 0) {
            return -1;
        }
        start += chunk;
    }
    return 0;
}

/* Write an intel hex file covering only the programmed bytes of the image.
 * Runs of programmed bytes are expanded to align-byte boundaries (padded
 * with surrounding image bytes) and merged before being written out */
static int writeHexFile(const char* hexPath, const char* imagePath,
                        const uint8_t* written, uint32_t imageSize,
                        uint32_t baseAddr, uint32_t align)
{
    FILE*    hexFile   = NULL;
    FILE*    imageFile = NULL;
    uint8_t* image     = NULL;
    uint32_t pos       = 0;
    uint32_t pendStart = 0;
    uint32_t pendEnd   = 0;
    int      havePend  = 0;
    uint16_t upper     = 0;
    int      rc        = 0;

    imageFile = fopen(imagePath, "rb");
    if (imageFile == NULL) {
        fprintf(stderr, "Error: Unable to open image file %s\n", imagePath);
        return -1;
    }
    image = malloc(imageSize);
    if (image == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(imageFile);
        return -1;
    }
    if (fread(image, 1, imageSize, imageFile) != imageSize) {
        fprintf(stderr, "Error: Failed to read image file %s\n", imagePath);
        fclose(imageFile);
        free(image);
        return -1;
    }
    fclose(imageFile);

    hexFile = fopen(hexPath, "w");
    if (hexFile == NULL) {
        fprintf(stderr, "Error: Unable to open hex file %s\n", hexPath);
        free(image);
        return -1;
    }

    while ((rc == 0) && (pos < imageSize)) {
        uint32_t start;
        uint32_t end;
        uint64_t alignedEnd;

        /* Find the next run of programmed bytes */
        while ((pos < imageSize) && (written[pos] == 0)) {
            pos++;
        }
        if (pos == imageSize) {
            break;
        }
        start = pos;
        while ((pos < imageSize) && (written[pos] != 0)) {
            pos++;
        }
        end = pos;

        /* Expand the run to align-byte boundaries */
        start -= start % align;
        alignedEnd = (((uint64_t)end + align - 1) / align) * align;
        if (alignedEnd > imageSize) {
            alignedEnd = imageSize;
        }
        end = (uint32_t)alignedEnd;

        /* Merge with the pending run if the expansion made them touch */
        if (havePend && (start <= pendEnd)) {
            if (end > pendEnd) {
                pendEnd = end;
            }
        }
        else {
            if (havePend) {
                rc = writeHexRange(hexFile, image, baseAddr, pendStart, pendEnd,
                                   &upper);
            }
            pendStart = start;
            pendEnd   = end;
            havePend  = 1;
        }
    }
    if ((rc == 0) && havePend) {
        rc =
            writeHexRange(hexFile, image, baseAddr, pendStart, pendEnd, &upper);
    }
    if (rc == 0) {
        /* End-of-file record */
        rc = writeHexRecord(hexFile, 1, 0, NULL, 0);
    }

    free(image);
    if ((fclose(hexFile) != 0) || (rc != 0)) {
        fprintf(stderr, "Error: Failed to write hex file %s\n", hexPath);
        return -1;
    }
    return 0;
}

/* Initialize the NVM and server */
static int initializeServer(whServerContext*      serverContext,
                            whNvmContext*         nvmContext,
                            const whServerConfig* serverConfig,
                            const whNvmConfig*    nvmConfig)
{
    /* Initialize the NVM context */
    int rc = wh_Nvm_Init(nvmContext, nvmConfig);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to initialize NVM, ret = %d\n", rc);
        return EXIT_FAILURE;
    }

    rc = wh_Server_Init(serverContext, (whServerConfig*)serverConfig);
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize wolfHSM server: ret = %d\n", rc);
        return rc;
    }
    return 0;
}

static void cleanupServer(whServerContext* serverContext)
{
    wh_Server_Cleanup(serverContext);
}

static void printUsage(const char* progName)
{
    fprintf(stderr,
            "Usage: %s [--test] [--image[=<file>]] [--size <size>] "
            "[--invert-erased-byte] [--hex[=<file>]] [--hex-base <addr>] "
            "[--hex-align <n>] <config-file>\n",
            progName);
}

int main(int argc, char* argv[])
{
    int                  rc = 0;
    int                  opt;
    char*                config_file        = NULL;
    char*                image_file         = DEFAULT_IMAGE_FILE;
    uint32_t             partition_size     = DEFAULT_PARTITION_SIZE;
    uint8_t              erased_byte        = DEFAULT_ERASED_BYTE;
    int                  invert_erased_byte = 0;
    char*                hex_file           = NULL; /* non-NULL enables hex */
    uint32_t             hex_base           = 0;
    uint32_t             hex_align          = 1;
    int                  hex_opts_given     = 0;
    uint8_t*             written            = NULL;
    uint32_t             image_size         = 0;
    static struct option long_options[]     = {
        {"test", no_argument, 0, 't'},
        {"image", optional_argument, 0, 'i'},
        {"size", required_argument, 0, 's'},
        {"invert-erased-byte", no_argument, 0, 'e'},
        {"hex", optional_argument, 0, 'x'},
        {"hex-base", required_argument, 0, 'b'},
        {"hex-align", required_argument, 0, 'a'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "ti::s:ex::b:a:", long_options,
                              NULL)) != -1) {
        switch (opt) {
            case 't':
                gTestMode = 1;
                break;
            case 'i':
                if (optarg) {
                    image_file = optarg;
                }
                break;
            case 's':
                if (strncmp(optarg, "0x", 2) == 0) {
                    partition_size = (uint32_t)strtoul(optarg + 2, NULL, 16);
                }
                else {
                    partition_size = (uint32_t)strtoul(optarg, NULL, 10);
                }
                if (partition_size == 0) {
                    fprintf(stderr, "Error: Invalid partition size\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'e':
                invert_erased_byte = 1;
                break;
            case 'x':
                hex_file = (optarg != NULL) ? optarg : DEFAULT_HEX_FILE;
                break;
            case 'b':
                if (parseUint32(optarg, &hex_base) != 0) {
                    fprintf(stderr, "Error: Invalid hex base address\n");
                    return EXIT_FAILURE;
                }
                hex_opts_given = 1;
                break;
            case 'a':
                if ((parseUint32(optarg, &hex_align) != 0) ||
                    (hex_align == 0)) {
                    fprintf(stderr, "Error: Invalid hex alignment\n");
                    return EXIT_FAILURE;
                }
                hex_opts_given = 1;
                break;
            default:
                printUsage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: Config file is mandatory\n");
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    config_file = argv[optind];

    if (invert_erased_byte) {
        erased_byte = 0x00;
    }

    if ((hex_file == NULL) && hex_opts_given) {
        fprintf(stderr, "Error: --hex-base and --hex-align require --hex\n");
        return EXIT_FAILURE;
    }

    if (hex_file != NULL) {
        uint64_t    total_size = (uint64_t)partition_size * 2;
        struct stat st;

        if (total_size > UINT32_MAX) {
            fprintf(stderr, "Error: Partition size too large\n");
            return EXIT_FAILURE;
        }
        image_size = (uint32_t)total_size;

        if (((uint64_t)hex_base + image_size) > 0x100000000ULL) {
            fprintf(stderr, "Error: hex base address plus image size exceeds "
                            "the 32-bit address space\n");
            return EXIT_FAILURE;
        }

        /* Alignment is applied to image offsets, so it only holds in the
         * device address space if the base is aligned too */
        if ((hex_base % hex_align) != 0) {
            fprintf(stderr, "Error: hex base address must be a multiple of "
                            "the hex alignment\n");
            return EXIT_FAILURE;
        }

        /* The hex file is built from the image file after it is written */
        if (strcmp(hex_file, image_file) == 0) {
            fprintf(stderr, "Error: hex file and image file must be "
                            "different\n");
            return EXIT_FAILURE;
        }

        /* Only bytes programmed during this run are tracked, so building on
         * top of an existing image would produce an incomplete hex file */
        if ((stat(image_file, &st) == 0) && (st.st_size != 0)) {
            fprintf(stderr,
                    "Error: image file %s already exists; delete it before "
                    "generating a hex file\n",
                    image_file);
            return EXIT_FAILURE;
        }

        written = calloc(image_size, 1);
        if (written == NULL) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return EXIT_FAILURE;
        }
    }

    /* Server configuration/context */
    whTransportServerCb            gTransportServerCb[1]      = {PTT_SERVER_CB};
    posixTransportTcpServerContext gTransportServerContext[1] = {};
    posixTransportTcpConfig        gTransportTcpConfig[1]     = {{
                   .server_ip_string = "127.0.0.1",
                   .server_port      = 8080,
    }};

    whCommServerConfig gCommServerConfig[1] = {{
        .transport_cb      = gTransportServerCb,
        .transport_context = (void*)gTransportServerContext,
        .transport_config  = (void*)gTransportTcpConfig,
        .server_id         = 34,
    }};

    /* POSIX flash file NVM configuration */
    posixFlashFileConfig gPosixFlashConfig = {
        .filename       = image_file,
        .partition_size = partition_size,
        .erased_byte    = erased_byte,
    };

    /* POSIX flash file context, wrapped with programmed-byte tracking */
    TrackedFlashContext gTrackedFlashContext = {.written = written};

    /* NVM Flash configuration using the tracked POSIX flash file */
    const whFlashCb  gFlashCb[1]     = {TRACKED_FLASH_CB};
    whNvmFlashConfig gNvmFlashConfig = {.cb      = gFlashCb,
                                        .context = &gTrackedFlashContext,
                                        .config  = &gPosixFlashConfig};

    whNvmFlashContext gNvmFlashContext = {0};
    const whNvmCb     gNvmCb[1]        = {WH_NVM_FLASH_CB};

    whNvmConfig gNvmConfig = {.cb      = (whNvmCb*)gNvmCb,
                              .context = &gNvmFlashContext,
                              .config  = &gNvmFlashConfig};

    whNvmContext gNvmContext = {0};

    /* Server configuration */
    whServerConfig gServerConfig = {
        .comm_config = gCommServerConfig,
        .nvm         = &gNvmContext,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = NULL,
#ifdef WOLFHSM_CFG_SHE_EXTENSION
        .she = NULL,
#endif /* WOLFHSM_CFG_SHE_EXTENSION */
#endif /* WOLFHSM_CFG_NO_CRYPTO */
#ifdef WOLFHSM_CFG_DMA
        .dmaConfig = NULL,
#endif /* WOLFHSM_CFG_DMA */
    };

    whServerContext gServerContext = {0};

    /* Initialize the server */
    rc = initializeServer(&gServerContext, &gNvmContext, &gServerConfig,
                          &gNvmConfig);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to initialize server, ret = %d\n", rc);
        free(written);
        return EXIT_FAILURE;
    }

    if (gTestMode) {
        /* Clear the intermediate file before processing */
        FILE* file = fopen(INTERMEDIATE_FILE, "w");
        if (file != NULL) {
            fclose(file);
        }
        else {
            fprintf(stderr, "Warning: Unable to clear intermediate file\n");
        }
    }

    /* Parse the configuration file */
    parseConfigFile(config_file);

    /* Process the entries */
    rc = processEntries(&gNvmContext);

    /* Free the allocated memory */
    freeEntries();

    /* Cleanup the server */
    cleanupServer(&gServerContext);

    if (rc != 0) {
        fprintf(stderr, "Error: entry processing failed, NVM image is "
                        "incomplete\n");
        free(written);
        return EXIT_FAILURE;
    }

    if (hex_file != NULL) {
        rc = writeHexFile(hex_file, image_file, written, image_size, hex_base,
                          hex_align);
        if (rc != 0) {
            free(written);
            return EXIT_FAILURE;
        }
    }
    free(written);

    return EXIT_SUCCESS;
}
