/* device_tget_inner harness types (namespace dti). Kept out of common.h so `make` stays incremental. */
#ifndef DEVICE_TGET_INNER_H
#define DEVICE_TGET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "common.h"

namespace dti {
#define DTI_MAXDM 8
#define DTI_LEFT 16          /* poisoned bytes in front of event_name (catches event_name[-1]) */
#define DTI_NAME_SZ 600
#define DTI_PAD 64


using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input;
using ccs::bus_data_type_string;
using ccs::raw_data_t; using ccs::bus_data_prop_t;
static const bus_error_t bus_error_invalid_operation = (bus_error_t)6;

#define MAX_EM_BUFF_SZ 1024
#define MAX_MACLIST_ITEMS 14
#define MAX_MACLIST_STRLEN 256
#define EM_BACKHAUL_DOWNMAC_ADDR 16
#define WIFI_80211_VARIANT_AC 0x20
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_string_t[32];
typedef char em_short_string_t[64];
typedef char em_long_string_t[128];
static const unsigned char ZERO_MAC_ADDR[6] = { 0, 0, 0, 0, 0, 0 };
typedef struct { int unused; } bus_user_data_t;

typedef struct { unsigned char dev_mac[6]; } em_device_id_t;
typedef struct { unsigned char mac[6]; } em_interface_t;
typedef struct {
    bool received; unsigned int boot_id;
    unsigned char client_id_len;     char client_id[256];
    unsigned char client_secret_len; char client_secret[256];
} em_ext_device_info_t;
typedef struct {
    em_device_id_t id;
    em_long_string_t manufacturer, serial_number, manufacturer_model;
    em_string_t software_ver, exec_env;
    char country_code[4];
    em_interface_t backhaul_mac;
    unsigned char num_backhaul_down_mac;
    em_string_t backhaul_down_mac[EM_BACKHAUL_DOWNMAC_ADDR];
    unsigned char rest_of_struct[256];   /* stands for the fields that follow the array in the real struct (runner poisons it) */
    int backhaul_media_type;
    unsigned int uptime, total_mem, free_mem, cached_mem;
    unsigned char cpu_load, cpu_temp;
    em_ext_device_info_t extended_info;
} em_device_info_t;
typedef struct { unsigned char onboarding_proto, integrity_algo, encryption_algo; } em_ieee_1905_security_cap_t;
typedef struct { bool mac_addr_valid; em_interface_t ruid; mac_address_t mac_addr; } em_affiliated_bsta_info_t;
typedef struct {
    bool mac_addr_valid, ap_mld_mac_addr_valid;
    mac_address_t mac_addr, ap_mld_mac_addr;
    bool str, nstr, emlsr, emlmr;
    unsigned char num_affiliated_bsta;
    em_affiliated_bsta_info_t affiliated_bsta[64];
} em_bsta_mld_info_t;

class dm_device_t { public: em_device_info_t info; em_device_info_t *get_device_info() { return &info; } };
class dm_easy_mesh_t {
public:
    int id; bool ctrl; bool no_dev; unsigned int nradios; bool bsta; em_bsta_mld_info_t bsm; em_ieee_1905_security_cap_t sec; bool has_sec;
    dm_device_t dev;
    int get_id() const { return id; }
    bool is_controller() { return ctrl; }
    dm_device_t *get_device() { return no_dev ? NULL : &dev; }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return has_sec ? &sec : NULL; }
    unsigned int get_num_radios() { return nradios; }
    bool is_bsta_mld_present() { return bsta; }
    em_bsta_mld_info_t &get_bsta_mld_info() { return bsm; }
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
    static void maclist_to_string(mac_address_t mac_list[], size_t mac_count, char *string, uint16_t str_len);
};
extern dm_easy_mesh_t *g_dm[DTI_MAXDM + 1];
extern int g_ndm;

typedef struct {
    int id;               /* dm instance number (get_id) */
    bool controller;      /* dm->is_controller() */
    bool no_device;       /* dm->get_device() == NULL */
    unsigned char mac;    /* last byte of dev_mac; 0 = all-zero MAC (skipped) */
    unsigned char bh_mac; /* last byte of backhaul MAC; 0 = zero MAC */
    int n_down;           /* num_backhaul_down_mac */
    int n_down_fill;      /* how many backhaul_down_mac entries are really filled (<=16) */
    bool full_down;       /* fill the down entries with 31 chars (no NUL room issue) */
    bool ext_received;
    bool has_sec;
    bool bsta_mld;
    int n_aff;            /* num_affiliated_bsta */
} dm_spec_t;

typedef struct {
    const char *test_name;
    const char *event;     /* NULL passes a NULL event_name; "" is the empty string */
    bool no_pdata;         /* p_data == NULL */
    dm_spec_t dms[DTI_MAXDM];
    int expect_rc;         /* 0 success, 2 invalid_input, 6 invalid_operation (stand-in values) */
    int expect_devices;    /* number of device "ID" properties reported, -1 = do not check */
    const char *has;       /* "name=value" that must appear in the recorded properties (NULL = no check) */
    const char *not_has;   /* must NOT appear */
    bool crash;            /* expected to abort (runs last; unforked unless FORK_CRASH=1) */
} test_case_t;

extern test_case_t suite[];
extern char name_store[DTI_LEFT + DTI_NAME_SZ + DTI_PAD];
extern int g_rc;
extern int g_raw_set;
extern int g_ndev;
extern char g_rec[];            /* recorded "idx:name=value\n" */
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_device_tget_inner(void);
#endif
