/* bstamld_get_inner harness types (namespace bml). Own header, kept out of common.h. */
#ifndef BSTAMLD_GET_INNER_H
#define BSTAMLD_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace bml {
#define BML_LEFT 16
#define BML_NAME_SZ 300
#define BML_PAD 64
#define BML_MAXAFF 64
using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input; using ccs::bus_error_invalid_namespace;
using ccs::raw_data_t;
/* stand-in value: only compared with itself (the real bus_error_destination_not_found comes from the bus library) */
static const bus_error_t bus_error_destination_not_found = (bus_error_t)100;

#define MAX_INSTANCE_LEN 32
#define MAX_MACLIST_ITEMS 14
#define MAX_MACLIST_STRLEN 256
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
static const unsigned char ZERO_MAC_ADDR[6] = { 0, 0, 0, 0, 0, 0 };
typedef struct { int unused; } bus_user_data_t;
typedef struct { unsigned char mac[6]; } em_interface_t;
typedef struct { bool mac_addr_valid; em_interface_t ruid; mac_address_t mac_addr; } em_affiliated_bsta_info_t;
typedef struct {
    bool mac_addr_valid, ap_mld_mac_addr_valid;
    mac_address_t mac_addr, ap_mld_mac_addr;
    bool str, nstr, emlsr, emlmr;
    unsigned char num_affiliated_bsta;
    em_affiliated_bsta_info_t affiliated_bsta[BML_MAXAFF];
    unsigned char rest_of_struct[256];     /* members after affiliated_bsta[] (runner poisons it) */
} em_bsta_mld_info_t;
class dm_easy_mesh_t {
public:
    bool bsta; em_bsta_mld_info_t bsm;
    bool is_bsta_mld_present() { return bsta; }
    em_bsta_mld_info_t &get_bsta_mld_info() { return bsm; }
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
    static void maclist_to_string(mac_address_t mac_list[], size_t mac_count, char *string, uint16_t str_len);
};
extern dm_easy_mesh_t *g_dm;

typedef struct {
    const char *test_name;
    const char *event;     /* NULL passes a NULL event_name */
    bool no_pdata;
    bool no_dm;            /* no device registered */
    bool no_bsta;          /* is_bsta_mld_present() false */
    bool mld_valid, bssid_valid;
    int n_aff;             /* num_affiliated_bsta */
    int expect_rc;         /* 0 success, 2 invalid_input, 25 invalid_namespace, 100 destination_not_found (stand-in) */
    const char *expect_val;/* recorded raw_data_set value, NULL = unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[BML_LEFT + BML_NAME_SZ + BML_PAD];
extern int g_rc;
extern int g_nset;
extern char g_val[512];
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_bstamld_get_inner(void);
#endif
