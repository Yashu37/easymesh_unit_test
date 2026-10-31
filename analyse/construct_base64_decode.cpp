/*
 * TEST CASES / CONSTRUCTOR: construct_base64_decode
 *
 * Mirrors the repo pattern (a *_suite[] of cases + a constructor that
 * loads each case), but base64_decode is a plain string->buffer function,
 * not a pcap/TLV message, so the "packet" here is just the input string
 * and the output buffer, instead of packet[].
 *
 * Each case names an exact output-buffer size. The runner
 * (base64_decode_test.cpp) poisons every output byte at or beyond that
 * size with ASan, so any write at/above the array size is reported, and
 * the global red-zone catches any write below index 0.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* shared state the runner reads (declared extern in common.h) */
char    b64_input[512];     /* writable copy of the case input   */
uint8_t b64_out[4096];      /* output buffer; tail poisoned       */
ssize_t b64_out_sz;         /* size handed to base64_decode()     */
const char *b64_case_name;  /* current case, for logging          */

/*
 * Test suite. expected_result is what base64_decode WOULD return if it did
 * not crash first (>=0 bytes for decodable input, -1 for a rejected input).
 * A crash shows up as an ASan abort before any result is compared.
 */
base64_test_case_t base64_decode_suite[] = {
    /* name                     input               out_sz  expected */
    { "valid_Zm9v_foo",         "Zm9v",             3,      3  },
    { "valid_Zm9vYmFy_foobar",  "Zm9vYmFy",         6,      6  },
    { "valid_pad1_Zm8=",        "Zm8=",             2,      2  },
    { "valid_pad2_Zg==",        "Zg==",             1,      1  },
    { "tight_out_Zm9v",         "Zm9v",             3,      3  },

    /* chars NOT in base64_table -> strchr walks a table with no NUL */
    { "invalid_char_at",        "@@@@",             3,     -1  },
    { "invalid_char_tilde",     "~~~~",             3,     -1  },
    { "invalid_trailing_byte",  "Zm9\x7f",          3,     -1  },

    /* larger / edge inputs */
    { "valid_long_12char",      "QUJDREVGR0hJSks=", 11,     11 },
    { "all_slashes",            "////",             3,      3  },
    { "all_plus",               "++++",             3,      3  },

    { NULL, NULL, 0, 0 }  /* sentinel */
};

/* Load one case into the shared input buffer + output size. */
void construct_base64_input(const base64_test_case_t *tc)
{
    b64_case_name = tc->test_name;

    memset(b64_input, 0, sizeof(b64_input));
    /* copy the raw input bytes (input may contain non-printable bytes) */
    size_t n = strlen(tc->input);
    if (n >= sizeof(b64_input)) n = sizeof(b64_input) - 1;
    memcpy(b64_input, tc->input, n);
    b64_input[n] = '\0';

    b64_out_sz = tc->out_sz;
}
