/* create_node harness types (namespace cnd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef CREATE_NODE_H
#define CREATE_NODE_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <vector>
#include "common.h"

namespace cnd {
#define CND_GUARD 64
typedef unsigned char mac_address_t[6];
typedef char em_interface_name_t[32];
typedef struct { em_interface_name_t name; mac_address_t mac; int media; } __attribute__((__packed__)) em_interface_t;
typedef int em_freq_band_t; typedef int em_profile_type_t; typedef int em_service_type_t;

class dm_easy_mesh_t {
public:
    static int name_from_mac_address(const mac_address_t *mac, char *ifname);
    static char *macbytes_to_string(mac_address_t mac, char *string);
};

extern int g_init_rc;        /* what em_t::init() returns */
extern bool g_throw_on_null_dm;   /* like the real em_t: the AL node throws when its data model is NULL (initialize_ec_manager() fails) */
extern bool g_ctor_throws;   /* em_t constructor throws std::runtime_error (EC manager init failure of the AL node) */
extern bool g_name_found;    /* name_from_mac_address() finds an interface */
extern int g_ctor_calls, g_init_calls;

class em_mgr_t;
class em_t {
public:
    em_interface_t ruid; bool is_al; bool dpp;
    em_t(em_interface_t *r, em_freq_band_t, dm_easy_mesh_t *dm_, em_mgr_t *, em_profile_type_t, em_service_type_t, bool al)
    { g_ctor_calls++; if (al && (g_ctor_throws || (g_throw_on_null_dm && !dm_))) throw std::runtime_error("Failed to initialize EC manager"); memcpy(&ruid, r, sizeof(ruid)); is_al = al; dpp = false; }
    void set_is_dpp_onboarding(bool b) { dpp = b; }
    int init() { g_init_calls++; return g_init_rc; }
};

typedef struct { char *key; em_t *em; } map_ent_t;
class em_mgr_t {
public:
    pthread_mutex_t m_mutex;
    std::vector<map_ent_t> m_map;
    em_mgr_t() { pthread_mutex_init(&m_mutex, NULL); }
    virtual ~em_mgr_t() {}
    virtual bool is_agent_dpp_onboarding() { return true; }
    bool has_node_(const char *k) { return map_get(k) != NULL; }
    /* like em_mgr_t::delete_node(): remove the node (key without "_al") from the map and delete it */
    void delete_node(em_interface_t *r)
    {   char k[32]; dm_easy_mesh_t::macbytes_to_string(r->mac, k);
        for (size_t i = 0; i < m_map.size(); i++) if (!strcmp(m_map[i].key, k)) { delete m_map[i].em; free(m_map[i].key); m_map.erase(m_map.begin() + i); return; } }
    em_t *map_get(const char *k) { for (auto &e : m_map) if (!strcmp(e.key, k)) return e.em; return NULL; }
    em_t *create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac, em_profile_type_t profile, em_service_type_t type);
};

typedef struct {
    const char *test_name;
    bool null_ruid;
    bool is_al;
    int init_rc;            /* em_t::init() result */
    bool ctor_throws;
    bool name_found;
    bool preexisting;       /* a node with the same key is already in the map */
    int expect;             /* 0 returns NULL, 1 returns a new node, 2 returns the existing node */
    int expect_map;         /* entries in the map afterwards */
    const char *expect_key; /* key of the newest entry (NULL = unchecked) */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern em_interface_t *g_ruid;     /* points into guarded storage */
extern unsigned char ruid_store[CND_GUARD + sizeof(em_interface_t) + CND_GUARD];
extern em_mgr_t *g_mgr;
extern em_t *g_ret;
void construct_input(const test_case_t *tc);
void invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_create_node(void);
#endif
