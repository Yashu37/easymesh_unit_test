/*
 * TEST CASES / CONSTRUCTOR: construct_key_unwrap
 *
 * kek = kek_len bytes (i*5+1), plaintext key = plain_len bytes (i*3+7); the wrapped key is produced by the OpenSSL AES key wrap
 * encrypt (RFC 3394), independently of the handler, and is plain_len + 8 bytes. Every buffer is exactly its length between two
 * poisoned 128 byte guards. out_buf -1 gives the unwrapped buffer the size the header documents (wrapped_len - 8), out_buf -2 the
 * size the real caller allocates (wrapped_len). PASS = return value and, for a valid key, *unwrapped_len == plain_len and the
 * unwrapped bytes equal the plaintext. Cases named clamp_* / rej_* ABORTED on the original code (memcpy(unwrapped, wrapped, wrapped_len)
 * wrote 8 bytes more than the documented wrapped_len - 8, NULL kek / wrapped / unwrapped / unwrapped_len): fix 2 writes only wrapped_len - 8
 * bytes, fix 1 returns 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "key_unwrap.h"

namespace aku {
static void mk(gbuf_t *b, size_t n, int mul, int add)
{
    b->n = n; b->raw = (uint8_t *)calloc(1, AKU_GUARD + n + AKU_GUARD); b->p = b->raw + AKU_GUARD;
    for (size_t i = 0; i < n; i++) b->p[i] = (uint8_t)(i * mul + add);
}
static void fr(gbuf_t *b) { free(b->raw); b->raw = b->p = NULL; b->n = 0; }

/* {name, kek_len, plain_len, wrapped_len, out_buf, tamper, null_kek, null_wrapped, null_out, null_outlen, expect_ret, check_output, crash} */
test_case_t suite[] = {
 {"ok_kek16_key16",                     16, 16, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek24_key16",                     24, 16, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek32_key16",                     32, 16, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek16_key24",                     16, 24, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek32_key32",                     32, 32, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek16_key40",                     16, 40, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek16_key64",                     16, 64, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_kek32_key1000",                   32, 1000, 0, -2, false, false, false, false, false, 1, true, false},
 {"ok_tampered_key_integrity_fails",    16, 32, 0, -2, true, false, false, false, false, 0, false, false},
 {"ok_kek_length_0_rejected",           0, 16, 0, -2, false, false, false, false, false, 0, false, false},
 {"ok_kek_length_15_rejected",          15, 16, 0, -2, false, false, false, false, false, 0, false, false},
 {"ok_kek_length_17_rejected",          17, 16, 0, -2, false, false, false, false, false, 0, false, false},
 {"ok_kek_length_33_rejected",          33, 16, 0, -2, false, false, false, false, false, 0, false, false},
 {"ok_wrapped_length_0_rejected",       16, 16, 1, -2, false, false, false, false, false, 0, false, false},
 {"ok_wrapped_length_8_rejected",       16, 16, 8, -2, false, false, false, false, false, 0, false, false},
 {"ok_wrapped_length_16_rejected",      16, 16, 16, -2, false, false, false, false, false, 0, false, false},
 {"ok_wrapped_length_23_rejected",      16, 16, 23, -2, false, false, false, false, false, 0, false, false},
 {"ok_wrapped_length_25_rejected",      16, 16, 25, -2, false, false, false, false, false, 0, false, false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_documented_buffer_kek16_key16", 16, 16, 0, -1, false, false, false, false, false, 1, true, false},
 {"clamp_documented_buffer_kek32_key64", 32, 64, 0, -1, false, false, false, false, false, 1, true, false},
 {"clamp_documented_buffer_tampered_key", 16, 32, 0, -1, true, false, false, false, false, 0, false, false},
 {"rej_null_wrapped",                 16, 16, 0, -2, false, false, true, false, false, 0, false, false},
 {"rej_null_unwrapped_buffer",        16, 16, 0, -2, false, false, false, true, false, 0, false, false},
 {"rej_null_unwrapped_len",           16, 16, 0, -2, false, false, false, false, true, 0, false, false},
 {"rej_null_kek",                     16, 16, 0, -2, false, true, false, false, false, 0, false, false},
 {NULL, 0, 0, 0, 0, false, false, false, false, false, 0, false, false}
};

/* independent reference: RFC 3394 wrap through the OpenSSL EVP API */
static size_t wrap_ref(const uint8_t *kek, size_t kl, const uint8_t *plain, size_t pl, uint8_t *out)
{
    const EVP_CIPHER *c = kl == 16 ? EVP_aes_128_wrap() : kl == 24 ? EVP_aes_192_wrap() : EVP_aes_256_wrap();
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new(); int l = 0, f = 0;
    EVP_CIPHER_CTX_set_flags(x, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    EVP_EncryptInit_ex(x, c, NULL, kek, NULL); EVP_CIPHER_CTX_set_padding(x, 0);
    EVP_EncryptUpdate(x, out, &l, plain, (int)pl); EVP_EncryptFinal_ex(x, out + l, &f);
    EVP_CIPHER_CTX_free(x); return (size_t)(l + f);
}

void construct_input(const test_case_t *tc)
{
    mk(&g_kek, tc->kek_len, 5, 1);
    mk(&g_plain, tc->plain_len, 3, 7);
    uint32_t wl = tc->wrapped_len ? tc->wrapped_len : tc->plain_len + 8;
    mk(&g_wrapped, wl, 11, 13);
    if (!tc->wrapped_len) {
        uint8_t *tmp = (uint8_t *)calloc(1, tc->plain_len + 64);
        wrap_ref(g_kek.p, tc->kek_len, g_plain.p, tc->plain_len, tmp); memcpy(g_wrapped.p, tmp, wl); free(tmp);
        if (tc->tamper) g_wrapped.p[wl / 2] ^= 0x5A;
    }
    size_t ob = tc->out_buf == -1 ? wl - 8 : tc->out_buf == -2 ? wl : (size_t)tc->out_buf;
    mk(&g_out, ob, 0, 0);
    g_ulen = 0xDEADBEEF;
}
void teardown(void) { fr(&g_kek); fr(&g_wrapped); fr(&g_out); fr(&g_plain); }
} /* namespace aku */
