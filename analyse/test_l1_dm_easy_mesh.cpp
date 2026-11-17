/*
 * get_radio_cap(mac) regression tests for PR #895 (RDKBDEV-3653), to be added to upstream
 * tests/test_l1_dm_easy_mesh.cpp after TEST(dm_easy_mesh_t, get_radio_cap_invalid_mac).
 *
 * Built with the harness copy of dm_easy_mesh_t::get_radio_cap() (radio_tget_params.cpp, fix 2
 * markers) - see the gtest_dm_easy_mesh Makefile target. The members after m_radio_cap[] are
 * poisoned explicitly, so a lookup that reads m_radio_cap[EM_MAX_BANDS] aborts under ASan: that
 * is what makes these cases fail on the original loop (i < m_num_radios) and pass with the fix.
 * The two TEST bodies are written for the upstream file (plain dm_easy_mesh_t, no poison).
 */
#include <gtest/gtest.h>
#include <sanitizer/asan_interface.h>
#include <cstring>
#include "radio_tget_params.h"

typedef rtp::dm_easy_mesh_t harness_mesh_t;   /* the harness copy; upstream uses dm_easy_mesh_t */
using rtp::mac_address_t;

namespace {
/* guard bytes after m_radio_cap[] are poisoned for the lifetime of the object */
struct poisoned_mesh_t {
    harness_mesh_t *mesh;
    poisoned_mesh_t() : mesh(new harness_mesh_t) {
        memset((void *)mesh, 0, sizeof(*mesh));
        __asan_poison_memory_region(mesh->after_cap, sizeof(mesh->after_cap));
    }
    ~poisoned_mesh_t() {
        __asan_unpoison_memory_region(mesh->after_cap, sizeof(mesh->after_cap));
        delete mesh;
    }
};
}

/* m_num_radios above EM_MAX_BANDS: a MAC that is not present must return NULL without reading past m_radio_cap[] */
TEST(dm_easy_mesh_t, get_radio_cap_count_above_max_not_found)
{
    poisoned_mesh_t pm;
    harness_mesh_t &mesh = *pm.mesh;
    mesh.m_num_radios = EM_MAX_BANDS + 1;
    for (int i = 0; i < EM_MAX_BANDS; i++) {
        mac_address_t mac = {0x00, 0x11, 0x22, 0x33, 0x44, static_cast<unsigned char>(i)};
        memcpy(mesh.m_radio_cap[i].m_radio_cap_info.ruid.mac, mac, sizeof(mac_address_t));
    }
    mac_address_t searchMac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_TRUE(mesh.get_radio_cap(searchMac) == nullptr);
}

/* m_num_radios above EM_MAX_BANDS: a MAC in the last valid slot must still be found */
TEST(dm_easy_mesh_t, get_radio_cap_count_above_max_last_slot_found)
{
    poisoned_mesh_t pm;
    harness_mesh_t &mesh = *pm.mesh;
    mesh.m_num_radios = EM_MAX_BANDS + 1;
    for (int i = 0; i < EM_MAX_BANDS - 1; i++) {
        mac_address_t mac = {0x00, 0x11, 0x22, 0x33, 0x44, static_cast<unsigned char>(i)};
        memcpy(mesh.m_radio_cap[i].m_radio_cap_info.ruid.mac, mac, sizeof(mac_address_t));
    }
    mac_address_t lastMac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    memcpy(mesh.m_radio_cap[EM_MAX_BANDS - 1].m_radio_cap_info.ruid.mac, lastMac, sizeof(mac_address_t));
    EXPECT_TRUE(mesh.get_radio_cap(lastMac) == &mesh.m_radio_cap[EM_MAX_BANDS - 1]);
}
