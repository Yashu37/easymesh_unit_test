/* dm_easy_mesh_t::encode_config_reset harness types (namespace ecr). Own header, kept out of common.h so `make` stays incremental. */
#ifndef CONFIG_RESET_H
#define CONFIG_RESET_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "common.h"

namespace ecr {
#define ECR_GUARD 128
#define EM_MAX_NET_SSIDS 5
#define EM_MAX_INTERFACES 8
#define EM_IO_BUFF_SZ 4096
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_long_string_t[128]; typedef char em_interface_name_t[32]; typedef char em_subdoc_data_buff_t[EM_IO_BUFF_SZ];
typedef int em_media_type_t;
typedef struct { em_interface_name_t name; mac_address_t mac; em_media_type_t media; } __attribute__((__packed__)) em_interface_t;
typedef struct { int name; em_subdoc_data_buff_t buff; } __attribute__((__packed__)) em_subdoc_info_t;
/* stand-ins for the network / network SSID objects: encode() writes the member the real one would read (a short string) */
class dm_network_t { public: char id[32]; void encode(cJSON *obj) { cJSON_AddStringToObject(obj, "ID", id); } };
class dm_network_ssid_t { public: char ssid[32]; void encode(cJSON *obj) { cJSON_AddStringToObject(obj, "SSID", ssid); } };

/* dm_easy_mesh_t cut down to the members encode_config_reset uses; after_interfaces / after_ssids stand for the members that follow the
 * arrays in the real class (poisoned by the runner) */
class dm_easy_mesh_t {
public:
    unsigned int m_num_interfaces;
    em_interface_t m_interfaces[EM_MAX_INTERFACES];
    unsigned char after_interfaces[ECR_GUARD];
    dm_network_t m_network;
    unsigned int m_num_net_ssids;
    dm_network_ssid_t m_network_ssid[EM_MAX_NET_SSIDS];
    unsigned char after_ssids[ECR_GUARD];
    static char *macbytes_to_string(mac_address_t mac, char *string);
    int encode_config_reset(em_subdoc_info_t *subdoc, const char *key);
};
typedef struct { unsigned char before[ECR_GUARD]; dm_easy_mesh_t dm; unsigned char after[ECR_GUARD]; em_subdoc_info_t subdoc; unsigned char after_subdoc[ECR_GUARD]; } box_t;

typedef struct {
    const char *test_name;
    unsigned int num_ifaces;
    int name_mode;          /* 0 "ethN", 1 first name 32 characters without NUL, 2 whole interface array filled with 'A' */
    unsigned int num_ssids;
    const char *key;        /* NULL, "" or text; "#N" = N characters */
    bool null_subdoc;
    int expect_ret;
    int expect_ifaces;      /* entries of Interfaces.List, -1 unchecked */
    int expect_ssids;       /* entries of NetworkSSIDList, -1 unchecked */
    const char *expect_iface0;  /* first interface string, NULL unchecked */
    int expect_parse;       /* 1: the buffer must hold complete JSON */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern box_t *g_box;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_config_reset(void);
#endif
