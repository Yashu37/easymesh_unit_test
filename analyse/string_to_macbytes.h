/* string_to_macbytes harness types (namespace stm). Own header, kept out of common.h so `make` stays incremental. */
#ifndef STRING_TO_MACBYTES_H
#define STRING_TO_MACBYTES_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace stm {
#define STM_LEFT 16          /* poisoned bytes in front of key */
#define STM_KEY_SZ 64
#define STM_PAD 64
#define STM_GUARD 32         /* poisoned bytes before / after bmac */
#define STM_SENTINEL 0x5a    /* bmac is pre-filled with it: "unchanged" = 5a:5a:5a:5a:5a:5a */
#ifndef MIN_MAC_LEN
#define MIN_MAC_LEN 12
#endif
typedef unsigned char mac_address_t[6];

class dm_easy_mesh_t {
public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
};

typedef struct {
    const char *test_name;
    const char *key;
    bool key_null;
    bool bmac_null;
    const char *expect_mac;   /* "xx:xx:xx:xx:xx:xx"; "5a:5a:5a:5a:5a:5a" = bmac must stay unchanged; NULL = unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char key_store[STM_LEFT + STM_KEY_SZ + STM_PAD];
extern unsigned char bmac_store[STM_GUARD + 6 + STM_GUARD];
void construct_input(const test_case_t *tc);
void invoke(const test_case_t *tc);
void dirty_stack(void);
void teardown(void);
}
void run_all_tests_string_to_macbytes(void);
#endif
