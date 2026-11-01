/*
 * HANDLER: onewifi_ovsdb_method_send_s
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_sync.c. No fixes.
 * C++-only change: "return false;" in the default case is written as
 * "return NULL;" -- same value (false == 0) but C++ rejects bool -> pointer.
 * Local arrays: err (pjs_errmsg_t = char[128]) and the struct rpc_response
 * res, whose error.message is char[64]; both are written only by
 * rpc_response_from_json. Caller input ovsdb_sock_path is poisoned by the
 * runner; err/res are internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - struct rpc_response / rpc_response_error: expanded from
 *     lib/ovsdb/ovsdb_jsonrpc.pjs.h with lib/pjs/pjs_struct.h.
 *   - rpc_response_from_json: test parser with the pjs rules -- "id" int,
 *     optional "error" {code, message}; a message that does not fit
 *     message[64] is rejected (pjs_string_t_from_json: strlen >= sz ->
 *     false); errors written with snprintf(err, sizeof(pjs_errmsg_t)).
 *   - ovsdb_write_s: stub returning the JSON reply chosen by the test case.
 *   - onewifi_ovsdb_jsonrpc_id_new: stub returning 42.
 *   - LOG/LOGE no-op.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define LOGE(...)     do { } while (0)

/* ovsdb_mt_t (lib/ovsdb/ovsdb.h) is in common.h */

struct rpc_response_error            /* PJS_INT(code) PJS_STRING_Q(message, 64) */
{
    int  code;
    char message[64];  bool message_exists;
};
struct rpc_response                  /* PJS_SUB_Q(error, rpc_response_error) PJS_INT(id) */
{
    struct rpc_response_error error;  bool error_exists;
    int  id;
};

static bool rpc_response_from_json(struct rpc_response *out, json_t *js, bool update, pjs_errmsg_t err)
{
    (void)update;
    memset(out, 0, sizeof(*out));
    json_t *jid = json_object_get(js, "id");
    if (!json_is_integer(jid)) { snprintf(err, sizeof(pjs_errmsg_t), "id: not an integer"); return false; }
    out->id = (int)json_integer_value(jid);
    json_t *je = json_object_get(js, "error");
    if (je && !json_is_null(je)) {
        out->error_exists = true;
        out->error.code = (int)json_integer_value(json_object_get(je, "code"));
        const char *m = json_string_value(json_object_get(je, "message"));
        if (m) {
            if (strlen(m) >= sizeof(out->error.message)) {
                snprintf(err, sizeof(pjs_errmsg_t), "message: string too long (%zu): %s", strlen(m), m);
                return false;
            }
            strcpy(out->error.message, m);
            out->error.message_exists = true;
        }
    }
    return true;
}

static json_t *ovsdb_write_s(char *sock, json_t *js)
{
    (void)js;
    oms_writes++;
    oms_sock_seen = strlen(sock);
    return oms_reply ? json_loads(oms_reply, 0, NULL) : NULL;
}
static int onewifi_ovsdb_jsonrpc_id_new(void) { return 42; }

/* --- copied verbatim from lib/ovsdb/ovsdb_sync.c --- */
json_t *onewifi_ovsdb_method_send_s(const char *ovsdb_sock_path,
        ovsdb_mt_t mt,
        json_t * jparams)
{

    int     rpc_id = 0;
    char    *method = NULL;
    json_t  *js = NULL;
    json_t  *jres = NULL;
    json_t  *retval = NULL;

    switch (mt)
    {
        case MT_ECHO:
            method = "echo";
            break;

        case MT_MONITOR:
            method = "monitor";
            break;

        case MT_TRANS:
            method = "transact";
            break;

        default:
            LOG(ERR, "unknown method");
            json_decref(jparams);
            return NULL;   /* C++ only: verbatim "return false;" (== 0 == NULL in C) */
    }

    js = json_object();

    if (0 < json_object_set_new(js, "method", json_string(method)))
    {
        LOGE("Error adding method key.");
    }

    if (0 < json_object_set_new(js, "params", jparams))
    {
        LOGE("Error adding params array.");
        json_decref(jparams);
    }

    rpc_id = onewifi_ovsdb_jsonrpc_id_new();
    if (0 < json_object_set_new(js, "id", json_integer(rpc_id)))
    {
        LOGE("Error adding id key.");
    }

    jres = ovsdb_write_s((char *)ovsdb_sock_path, js);
    if (jres == NULL)
    {
        LOGE("Sync: Error sending OVSDB JSON-RPC request.");
        goto error;
    }

    struct rpc_response res;
    pjs_errmsg_t err;
    if (!rpc_response_from_json(&res, jres, false, err))
    {
        LOGE("Sync: Error parsing OVSDB response: %s", err);
        goto error;
    }

    if (res.id != rpc_id)
    {
        LOGE("Sync: JSON-RPC id mismatch: %d != %d", res.id, rpc_id);
        goto error;
    }

    if (res.error_exists)
    {
        LOGE("Sync: Error processing JSON-RPC response: code:%d message:%s\n",
                res.error.code,
                res.error.message);
        goto error;
    }

    /* Everything OK, return the result object */
    retval = json_object_get(jres, "result");

    /* Grab a reference to the retval object */
    json_incref(retval);

error:
    if (js != NULL) json_decref(js);
    if (jres != NULL) json_decref(jres);

    return retval;
}
