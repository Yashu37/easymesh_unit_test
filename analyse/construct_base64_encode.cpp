/*
 * TEST CASES / CONSTRUCTOR: construct_base64_encode
 *
 * base64_encode(char *out, ssize_t out_sz, void *input, ssize_t input_sz).
 * The "packet" here is the input byte buffer + the output buffer.
 *
 * The runner poisons every input byte at/beyond input_sz AND every output
 * byte at/beyond out_sz, so ASan reports an over-read of the input or an
 * over-write of the output (index at/above array size); the global
 * red-zones catch any access below index 0.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* shared state the runner reads (declared extern in common.h) */
uint8_t b64e_in[512];       /* input bytes; tail poisoned         */
char    b64e_out[4096];     /* output buffer; tail poisoned       */
ssize_t b64e_in_sz;         /* input_sz handed to base64_encode() */
ssize_t b64e_out_sz;        /* out_sz   handed to base64_encode() */
const char *b64e_case_name;

/*
 * expected_result = what base64_encode returns if it does not crash:
 *   groups*4 + 1  (4 chars per 3 input bytes, rounded up, plus the NUL),
 *   or -1 when the output buffer is too small (guard rejects it).
 */
base64_enc_test_case_t base64_encode_suite[] = {
    /* name                 input (bytes)       in_sz  out_sz  expected */
    { "enc_foo",            "foo",               3,     5,      5  },  /* -> "Zm9v" */
    { "enc_fo",             "fo",                2,     5,      5  },  /* -> "Zm8=" */
    { "enc_f",              "f",                 1,     5,      5  },  /* -> "Zg==" */
    { "enc_foobar",         "foobar",            6,     9,      9  },  /* -> "Zm9vYmFy" */
    { "enc_empty",          "",                  0,     1,      1  },  /* -> "" + NUL */

    /* output buffer sized to the exact minimum the guard allows */
    { "enc_tight_foo",      "foo",               3,     5,      5  },
    { "enc_tight_f",        "f",                 1,     5,      5  },

    /* output buffer one byte too small -> guard must reject with -1 */
    { "enc_too_small_foo",  "foo",               3,     4,     -1  },
    { "enc_too_small_f",    "f",                 1,     4,     -1  },
    { "enc_too_small_6",    "foobar",            6,     8,     -1  },

    /* high bytes / longer inputs (multiple rounds) */
    { "enc_highbytes",      "\xff\xff\xff",      3,     5,      5  },
    { "enc_7bytes",         "abcdefg",           7,    13,     13  },

    { NULL, NULL, 0, 0, 0 }  /* sentinel */
};

/* Load one case into the shared input/output buffers and sizes. */
void construct_base64_encode_input(const base64_enc_test_case_t *tc)
{
    b64e_case_name = tc->test_name;

    memset(b64e_in, 0, sizeof(b64e_in));
    ssize_t n = tc->in_sz;
    if (n > (ssize_t)sizeof(b64e_in)) n = sizeof(b64e_in);
    if (n > 0) memcpy(b64e_in, tc->input, n);

    b64e_in_sz  = tc->in_sz;
    b64e_out_sz = tc->out_sz;
}
