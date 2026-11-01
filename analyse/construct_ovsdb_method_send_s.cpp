/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_method_send_s
 *
 * onewifi_ovsdb_method_send_s(sock, mt, params) builds {"method","params",
 * "id":42}, sends it (ovsdb_write_s stubbed -> reply chosen per case) and
 * parses the reply into struct rpc_response (error.message is char[64]).
 *
 * Cases: unknown method, echo OK, transact OK, no reply, reply without id,
 * id mismatch, error with a 63-char message (fits), error with a 200-char
 * message (rejected by the parser), and a 255-char socket path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        oms_sock[256];
size_t      oms_sock_len, oms_sock_seen;
int         oms_writes;
const char *oms_reply;
static char oms_reply_buf[1024];

ovsdb_method_send_s_test_case_t ovsdb_method_send_s_suite[] = {
    /* name                mt  reply                                                   sock_fill result writes */
    { "unknown_method",     9, NULL,                                                       0,     0,    0 },
    { "echo_ok",            0, "{\"id\":42,\"error\":null,\"result\":[]}",                 0,     1,    1 },
    { "transact_ok",        2, "{\"id\":42,\"error\":null,\"result\":[{\"count\":1}]}",    0,     1,    1 },
    { "no_reply",           2, NULL,                                                       0,     0,    1 },
    { "reply_no_id",        2, "{\"result\":[]}",                                          0,     0,    1 },
    { "id_mismatch",        2, "{\"id\":7,\"error\":null,\"result\":[]}",                  0,     0,    1 },
    { "error_msg_63",       2, "ERR63",                                                    0,     0,    1 },
    { "error_msg_200",      2, "ERR200",                                                   0,     0,    1 },
    { "sock_path_255",      2, "{\"id\":42,\"error\":null,\"result\":[]}",               255,     1,    1 },

    { NULL, 0, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_method_send_s_input(const ovsdb_method_send_s_test_case_t *tc)
{
    memset(oms_sock, 0, sizeof(oms_sock));
    if (tc->sock_fill) memset(oms_sock, 's', (size_t)tc->sock_fill);
    else               snprintf(oms_sock, sizeof(oms_sock), "/var/run/openvswitch/db.sock");
    oms_sock_len = strlen(oms_sock);

    if (tc->reply && !strncmp(tc->reply, "ERR", 3)) {
        int n = atoi(tc->reply + 3);
        char msg[256]; memset(msg, 'm', (size_t)n); msg[n] = 0;
        snprintf(oms_reply_buf, sizeof(oms_reply_buf),
                 "{\"id\":42,\"error\":{\"code\":5,\"message\":\"%s\"},\"result\":null}", msg);
        oms_reply = oms_reply_buf;
    } else {
        oms_reply = tc->reply;
    }
    oms_writes = 0;
    oms_sock_seen = 0;
}
