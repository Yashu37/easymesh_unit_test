/* create_data_model harness types (namespace cdm). Own header, kept out of common.h so `make` stays incremental. */
#ifndef CREATE_DATA_MODEL_H
#define CREATE_DATA_MODEL_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string>
#include <vector>
#include "common.h"

namespace cdm {
#define CDM_GUARD 256
#define CDM_LEFT 16
#define CDM_NAME_SZ 400
#define CDM_PAD 64
#define EM_MAX_PRE_SET_CHANNELS 6
#define GLOBAL_NET_ID "OneWifiMesh"
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_short_string_t[64];
typedef char em_long_string_t[128];
typedef char em_2xlong_string_t[256];
typedef char em_interface_name_t[32];
typedef int em_profile_type_t; typedef int em_media_type_t;
typedef struct { em_interface_name_t name; mac_address_t mac; em_media_type_t media; } __attribute__((__packed__)) em_interface_t;
typedef struct { int id_type; } em_policy_t;
typedef struct { em_long_string_t net_id; mac_address_t dev_mac; em_media_type_t media; } em_device_id_t;
typedef struct { em_long_string_t id; em_interface_t ctrl_id; em_interface_t colocated_agent_id; em_media_type_t media; } em_network_info_t;
typedef struct { em_device_id_t id; em_interface_t intf; em_interface_t backhaul_mac; em_profile_type_t profile;
                 unsigned char after_id[CDM_GUARD]; /* members behind id[] of the real em_device_info_t, poisoned by the runner */ } em_device_info_t;
class dm_policy_t { public: em_policy_t m_policy; dm_policy_t(const em_policy_t &p) { m_policy = p; } };
class dm_op_class_t { public: int op_class; dm_op_class_t(int c = 0) { op_class = c; } };
class dm_network_ssid_t { public: int ssid; };
class dm_network_t {
public:
    em_network_info_t m_net_info; mac_address_t coloc_mac; int coloc_set;
    void set_colocated_agent_interface_mac(unsigned char *m) { memcpy(coloc_mac, m, 6); coloc_set++; }
    unsigned char *get_colocated_agent_interface_mac() { return coloc_mac; }
};
class dm_device_t { public: em_device_info_t m_device_info; void update_easymesh_json_cfg(bool) {} };

class dm_easy_mesh_t; void on_dm_created(dm_easy_mesh_t *dm);
extern bool g_name_found;            /* name_from_mac_address() finds the MAC on this device (agent is colocated) */
class dm_easy_mesh_t {
public:
    dm_device_t m_device; dm_network_t m_network; bool controller, colocated; int num_policy, num_channels, id, db_cfg_calls;
    unsigned int num_ssid; dm_network_ssid_t ssid[4];
    void init();   /* zeroes the object, then calls on_dm_created() (the runner poisons the guard behind id[] there) */
    void set_controller(bool c) { controller = c; }
    void set_colocated(bool c) { colocated = c; }
    dm_device_t *get_device() { return &m_device; }
    dm_network_t *get_network() { return &m_network; }
    void set_id() { id = 7; } int get_id() { return id; }
    void set_channels_list(dm_op_class_t *, unsigned int n) { num_channels = (int)n; }
    void set_policy(dm_policy_t) { num_policy++; }
    int get_num_policy() { return num_policy; }
    unsigned int get_num_network_ssid() { return num_ssid; }
    void set_num_network_ssid(unsigned int n) { num_ssid = n > 4 ? 4 : n; }
    dm_network_ssid_t *get_network_ssid(unsigned int i) { return &ssid[i]; }
    void set_db_cfg_param(int, const char *) { db_cfg_calls++; }
    static int name_from_mac_address(const mac_address_t *, char *) { return g_name_found ? 0 : -1; }
    static char *macbytes_to_string(unsigned char *mac, char *s) { sprintf(s, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return s; }
};
#define db_cfg_type_network_list_update 1
typedef struct { std::vector<std::pair<char *, void *>> v; } hash_map_t;
void *hash_map_get_first(hash_map_t *m); void *hash_map_get_next(hash_map_t *m, void *cur);
void *hash_map_get(hash_map_t *m, const char *key); void hash_map_put(hash_map_t *m, char *key, void *val);
namespace util { inline std::string mac_to_string(const unsigned char *m) { char b[24]; sprintf(b, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); return b; } }

class dm_easy_mesh_list_t {
public:
    hash_map_t *m_list;
    dm_network_t *get_network(const char *key);
    dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac);
    dm_easy_mesh_t *create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile, bool controller);
};

typedef struct {
    const char *test_name;
    const char *net_id;      /* NULL passes NULL; "@LONGnnn" = net_id of nnn 'N' characters */
    int long_len;            /* > 0: net_id is this many 'N' characters */
    bool al_null;
    bool controller;
    bool name_found;         /* agent: the AL MAC exists on this device (colocated) */
    int pre;                 /* 0 none, 1 reference dm of net_id exists (2 SSIDs), 2 network exists but its controller dm is not in the list, 3 reference dm + controller dm for colocated, 4 network exists, ref dm missing, other mac */
    int expect;              /* 0 returns NULL, 1 returns a data model */
    int expect_list;         /* entries in the list afterwards */
    int expect_flags;        /* bit0 controller, bit1 colocated, bit2 set_id called, -1 unchecked */
    int expect_ssids;        /* network ssids of the new dm, -1 unchecked */
    int expect_findable;     /* 1 = get_data_model(net_id, al mac) must find the new dm, -1 unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[CDM_LEFT + CDM_NAME_SZ + CDM_PAD];
extern em_interface_t *g_al; extern unsigned char al_store[CDM_GUARD + sizeof(em_interface_t) + CDM_GUARD];
extern dm_easy_mesh_list_t *g_list; extern dm_easy_mesh_t *g_ret; extern std::vector<dm_easy_mesh_t *> g_dms;
void construct_input(const test_case_t *tc);
void invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_create_data_model(void);
#endif
