/*
 * TEST CASES / CONSTRUCTOR: construct_log_severity_parse_sink
 *
 * log_severity_parse_sink(sink, sevstr) parses a comma/space-separated list
 * of "SEVERITY" or "module:SEVERITY" tokens into psevstr[256]. Cases: valid
 * default severity, module:severity, a multi-token list, invalid severity,
 * invalid module, NULL input, a too-long (>=256) string (rejected by the
 * guard), and a 255-char string that fills psevstr to the brim.
 *
 * sevstr is runner-owned (poisoned tail by the runner).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        lsp_in[512];
size_t      lsp_in_len;
int         lsp_null;
const char *lsp_case_name;

log_sev_test_case_t log_sev_suite[] = {
    /* name              input                 fill_len  null  expect_ret */
    { "valid_debug",     "DEBUG",                0,       0,     1 },
    { "module_sev",      "wifi:INFO",            0,       0,     1 },
    { "multi_token",     "DEBUG, wifi:INFO, core:ERR", 0, 0,     1 },
    { "invalid_sev",     "BOGUS",                0,       0,     0 },
    { "invalid_module",  "badmod:DEBUG",         0,       0,     0 },
    { "null_input",      NULL,                   0,       1,     0 },
    { "too_long_300",    "DEBUG",                300,     0,     0 },   /* strlen>=256 -> guard rejects */
    { "fill_255",        "DEBUG",                255,     0,     0 },   /* fills psevstr; token invalid -> false */

    { NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_log_sev_input(const log_sev_test_case_t *tc)
{
    lsp_case_name = tc->test_name;
    lsp_null = tc->null;
    memset(lsp_in, 0, sizeof(lsp_in));

    if (tc->null) { lsp_in_len = 0; return; }

    if (tc->fill_len > 0) {
        /* base token then 'A' padding to reach fill_len total */
        int n = snprintf(lsp_in, sizeof(lsp_in), "%s", tc->input);
        while (n < tc->fill_len && (size_t)(n + 1) < sizeof(lsp_in)) lsp_in[n++] = 'A';
        lsp_in[n] = '\0';
    } else {
        snprintf(lsp_in, sizeof(lsp_in), "%s", tc->input);
    }
    lsp_in_len = strlen(lsp_in);
}
