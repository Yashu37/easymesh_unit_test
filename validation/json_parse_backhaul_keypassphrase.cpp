/*
 * HANDLER: json_parse_backhaul_keypassphrase
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:92 (~/Desktop/G/rdk-wifi-hal).  The function is a one-line
 * wrapper around json_parse_string(), so the REAL chain is copied VERBATIM and linked with the real libcjson:
 *   json_parse_string  src/wifi_hal_rdk_util.c:528
 *   json_open_file     src/wifi_hal_rdk_util.c:488
 * With RDK_JBK_FIX 0 all three are the verbatim originals (reproduces the findings); with RDK_JBK_FIX 1 they carry FIX 1..4.
 * The only redirection is the file path: fopen("/nvram/EasymeshCfg.json") (EM_CFG_FILE) opens the runner's temporary file.
 * The prints are the real macros over the log sink.  The static function is reached through hwr_jbk_call() (same TU).
 */
#include "hwr_jbk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <cjson/cJSON.h>

/* 1 = with FIX 1..4, 0 = original unfixed functions (set to 0 to reproduce the findings) */
#define RDK_JBK_FIX  0

#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define EM_CFG_FILE "/nvram/EasymeshCfg.json"
#define MAX_KEYPASSPHRASE_LEN 129      /* platform.c:43 */
#define fopen hwr_jbk_fopen

/* --- src/wifi_hal_rdk_util.c:488 --- */
#if RDK_JBK_FIX
cJSON *json_open_file(const char *file_name)
{
    FILE *fp;
    cJSON *json = NULL;
    size_t len;
    char *buff;

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d: Failed (err=%d, msg=%s) to open file:%s\n", __func__, __LINE__,
            errno, strerror(errno), file_name);
        return json;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    /* FIX 4: ftell() returns -1 on error (len == (size_t)-1, which is not UINT_MAX on 64 bit), and the buffer was not
     * NUL terminated although cJSON_GetErrorPtr() points into it and is printed with %s on every parse error
     * (heap-buffer-overflow read).  The buffer gets one extra byte holding the terminator. */
    if (len == (size_t)-1 || len == UINT_MAX) {
        fclose(fp);
        return json;
    }
    fseek(fp, 0, SEEK_SET);

    buff = malloc(len + 1);
    if (buff == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate %zu bytes for json file\n", __func__,
            __LINE__, len);
        fclose(fp);
        return NULL;
    }
    len = fread(buff, 1, len, fp);
    buff[len] = '\0';
    json = cJSON_ParseWithLength(buff, len);
    if (json == NULL) {
        const char *const error_ptr = cJSON_GetErrorPtr();
        wifi_hal_error_print("%s:%d: Error json file parse: %s\n", __func__, __LINE__,
            (error_ptr ? error_ptr : "UNKNOWN"));
    }
    free(buff);
    fclose(fp);
    return json;
}
#else
cJSON *json_open_file(const char *file_name)
{
    FILE *fp;
    cJSON *json = NULL;
    size_t len;
    char *buff;

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d: Failed (err=%d, msg=%s) to open file:%s\n", __func__, __LINE__,
            errno, strerror(errno), file_name);
        return json;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    if (len == UINT_MAX) {
        fclose(fp);
        return json;
    }
    fseek(fp, 0, SEEK_SET);

    buff = malloc(len);
    if (buff == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate %zu bytes for json file\n", __func__,
            __LINE__, len);
        fclose(fp);
        return NULL;
    }
    len = fread(buff, 1, len, fp);
    json = cJSON_ParseWithLength(buff, len);
    if (json == NULL) {
        const char *const error_ptr = cJSON_GetErrorPtr();
        wifi_hal_error_print("%s:%d: Error json file parse: %s\n", __func__, __LINE__,
            (error_ptr ? error_ptr : "UNKNOWN"));
    }
    free(buff);
    fclose(fp);
    return json;
}
#endif

/* --- src/wifi_hal_rdk_util.c:528 --- */
#if RDK_JBK_FIX
int json_parse_string(const char* file_name, const char *item_name, char *val, size_t len)
{
    cJSON *item;
    cJSON *json;
    const char *str;

    /* FIX 1: NULL file_name / item_name / val and len == 0 were dereferenced / indexed (val[len-1]) unchecked. */
    if (file_name == NULL || item_name == NULL || val == NULL || len == 0) {
        wifi_hal_error_print("%s:%d: invalid argument\n", __func__, __LINE__);
        return -1;
    }

    json = json_open_file(file_name);
    if (json == NULL) {
        return -1;
    }

    item = cJSON_GetObjectItem(json, item_name);
    if (!cJSON_IsString(item)) {
        wifi_hal_error_print("%s:%d: (%s) does "
                             "not exist or is not a string\n",
            __func__, __LINE__, item_name);
        cJSON_Delete(json);
        return -1;
    }
    str = cJSON_GetStringValue(item);
    /* FIX 2: a value that does not fit (strlen >= len) was cut at len-1 bytes silently and reported as success - a
     * truncated passphrase / SSID / MAC was then used.  It is now an error and val is left untouched. */
    if (strlen(str) >= len) {
        wifi_hal_error_print("%s:%d: (%s) value does not fit in %zu bytes\n", __func__, __LINE__, item_name, len);
        cJSON_Delete(json);
        return -1;
    }
    memcpy(val, str, strlen(str) + 1);

    cJSON_Delete(json);
    return 0;
}
#else
int json_parse_string(const char* file_name, const char *item_name, char *val, size_t len)
{
    cJSON *item;
    cJSON *json;

    json = json_open_file(file_name);
    if (json == NULL) {
        return -1;
    }

    item = cJSON_GetObjectItem(json, item_name);
    if (!cJSON_IsString(item)) {
        wifi_hal_error_print("%s:%d: (%s) does "
                             "not exist or is not a string\n",
            __func__, __LINE__, item_name);
        cJSON_Delete(json);
        return -1;
    }
    strncpy(val, cJSON_GetStringValue(item), len);
    val[len-1] = '\0';

    cJSON_Delete(json);
    return 0;
}
#endif

/* --- platform/banana-pi/platform.c:92 --- */
#if RDK_JBK_FIX
static int json_parse_backhaul_keypassphrase(char *backhaul_keypassphrase)
{
    /* FIX 3: an empty "Backhaul_KeyPassphrase": "" was returned as success, so the caller used an empty
     * passphrase instead of falling back to the nvram default.  An empty value is now "not found"; it is parsed into
     * a local buffer so out is not touched on any failure. */
    char tmp[MAX_KEYPASSPHRASE_LEN] = { 0 };

    if (json_parse_string(EM_CFG_FILE, "Backhaul_KeyPassphrase", tmp, MAX_KEYPASSPHRASE_LEN) != 0) {
        return -1;
    }
    if (tmp[0] == '\0' || backhaul_keypassphrase == NULL) {
        return -1;
    }
    memcpy(backhaul_keypassphrase, tmp, strlen(tmp) + 1);
    return 0;
}
#else
static int json_parse_backhaul_keypassphrase(char *backhaul_keypassphrase)
{
    return json_parse_string(EM_CFG_FILE, "Backhaul_KeyPassphrase", backhaul_keypassphrase,
        MAX_KEYPASSPHRASE_LEN);
}
#endif

extern "C" int hwr_jbk_call(char *out)
{
    return json_parse_backhaul_keypassphrase(out);
}
