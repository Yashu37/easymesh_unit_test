/* em_crypto_t::hash_to_hex_string harness types (namespace hhx). Own header, kept out of common.h so `make` stays incremental. */
#ifndef HASH_HEX_H
#define HASH_HEX_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "common.h"

namespace hhx {
#define HHX_GUARD 128
class em_crypto_t {
public:
    static std::string hash_to_hex_string(const uint8_t *hash, size_t hash_len);
    static std::string hash_to_hex_string(const std::vector<uint8_t>& hash);
};
/* the hash handed to the function sits between poisoned guards: [before 128][len bytes][after 128] */
typedef struct {
    const char *test_name;
    size_t len;
    int fill;            /* 0 all zero, 1 byte i = (i*7+3) & 0xFF, 2 all 0xFF, 3 byte i = i & 0xFF */
    bool null_hash;      /* pass NULL as the hash pointer */
    bool use_vector;     /* call the std::vector overload */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern uint8_t *g_raw;   /* guard + hash + guard */
extern uint8_t *g_hash;  /* g_raw + HHX_GUARD */
extern size_t g_len;
void construct_input(const test_case_t *tc);
std::string invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_hash_hex(void);
#endif
