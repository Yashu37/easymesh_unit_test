/*
 * TEST CASES / CONSTRUCTOR: construct_parse_uri
 *
 * parse_uri(uri, proto, proto_size, host, host_size, port) splits a
 * "proto:host:port" string. Cases cover valid ssl/tcp URIs, an unsupported
 * proto, missing port, a very long URI (> tmp[512]) to stress the tmp copy,
 * a very long host to stress the bounded output copy, and -- the suspected
 * crash -- a URI made of only delimiter(s), where strtok_r returns NULL for
 * tproto and strcmp(tproto, ...) dereferences NULL.
 *
 * The runner owns the input uri buffer and the proto/host output buffers
 * and poisons their tails.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        puri_in[1024];      /* input URI (poisoned tail)   */
size_t      puri_in_len;
const char *puri_case_name;

parse_uri_test_case_t parse_uri_suite[] = {
    /* name                 uri / fill                 use_fill fill_ch fill_len  expect_ret */
    { "valid_ssl",          "ssl:1.2.3.4:443",          0, 0,   0,   1 },
    { "valid_tcp",          "tcp:host.example:8080",    0, 0,   0,   1 },
    { "unsupported_proto",  "ftp:host:21",              0, 0,   0,   0 },
    { "missing_port",       "ssl:host",                 0, 0,   0,   0 },
    { "empty_uri",          "",                         0, 0,   0,   0 },
    { "long_uri_600",       "ssl:",                     1, 'h', 600, 0 },  /* > tmp[512]; truncated host, no port -> false */
    { "long_host",          NULL,                       2, 'h', 300, 1 },  /* valid proto/port, long host -> bounded copy */
    /* suspected NULL-deref crashes LAST (a crash aborts the run) */
    { "only_colon",         ":",                        0, 0,   0,  -1 },
    { "two_colons",         "::",                       0, 0,   0,  -1 },

    { NULL, NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_parse_uri_input(const parse_uri_test_case_t *tc)
{
    puri_case_name = tc->test_name;
    memset(puri_in, 0, sizeof(puri_in));

    if (tc->use_fill == 1) {
        /* "ssl:" + fill_len copies of fill_ch  (makes a URI longer than tmp[512]) */
        int n = snprintf(puri_in, sizeof(puri_in), "%s", tc->uri);
        for (int i = 0; i < tc->fill_len && (size_t)(n + 1) < sizeof(puri_in); i++)
            puri_in[n++] = tc->fill_ch;
        puri_in[n] = '\0';
    } else if (tc->use_fill == 2) {
        /* "ssl:" + long host + ":443" */
        int n = snprintf(puri_in, sizeof(puri_in), "ssl:");
        for (int i = 0; i < tc->fill_len && (size_t)(n + 6) < sizeof(puri_in); i++)
            puri_in[n++] = tc->fill_ch;
        snprintf(puri_in + n, sizeof(puri_in) - n, ":443");
    } else {
        snprintf(puri_in, sizeof(puri_in), "%s", tc->uri ? tc->uri : "");
    }

    puri_in_len = strlen(puri_in);
}
