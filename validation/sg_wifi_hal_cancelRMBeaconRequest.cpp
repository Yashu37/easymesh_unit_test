/*
 * HANDLER: wifi_hal_cancelRMBeaconRequest (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4090-4119 (~/Desktop/G/rdk-wifi-hal) together with the tables it works on (src/wifi_hal.c:3901-3903) and the bit helpers of
 * src/wifi_hal_priv.h:1444-1471 (u8_bitmap, get_bit_u8, set_bit_u8, reset_bit_u8).  This file holds the ORIGINAL code (no fixes).  It rejects apIndex >= MAX_AP_INDEX, then under g_wifi_hal.hapd_lock
 * looks up the VAP recorded as the sender of the token (clearing that record), keeps the "requested" bit when another VAP's request with the same token was sent on the same VAP, and otherwise clears the
 * bit with reset_bit_u8().
 *
 * Scaffolding only: g_wifi_hal is a stand-in holding the mutex hapd_lock; MAX_AP_INDEX is 15 (VAP_REINDEX off); hwr_wcb_* accessors expose the tables to the runner; the *_print macros go to the log sink
 * hwr_print.  Renamed hwr_sg_wifi_hal_cancelRMBeaconRequest.
 */
#include "hwr_wcb.h"
#include <stdio.h>
#include <string.h>

#define MAX_AP_INDEX 15
typedef uint8_t u8;
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
static struct { pthread_mutex_t hapd_lock; } hwr_wcb_g = { PTHREAD_MUTEX_INITIALIZER };
#define g_wifi_hal hwr_wcb_g
#define wifi_hal_cancelRMBeaconRequest hwr_sg_wifi_hal_cancelRMBeaconRequest
/* src/wifi_hal.c:2628-2634 */
#define _IS_INVALID_ARG(expr) ({ \
    bool __not_valid = (expr); \
    if (__not_valid) { \
        wifi_hal_error_print("%s:%d: Invalid argument; " #expr "\n", __func__, __LINE__); \
    } \
    __not_valid; \
})

/* src/wifi_hal_priv.h:1444-1471 */
typedef unsigned long bitmap_type;
#define BITS_PER_ULONG (sizeof(bitmap_type) * 8)

/* bitmap for 256 bits */
typedef bitmap_type u8_bitmap[256 / BITS_PER_ULONG];

static inline u8 get_bit_u8(u8_bitmap bits, u8 bit)
{
    bitmap_type *word = &bits[bit / BITS_PER_ULONG];
    return !!((*word) & (1 << (bit % BITS_PER_ULONG)));
}

static inline void set_bit_u8(u8_bitmap bits, u8 bit)
{
    bitmap_type *word = &bits[bit / BITS_PER_ULONG];
    (*word) |= 1 << (bit % BITS_PER_ULONG);
}

static inline void reset_bit_u8(u8_bitmap bits, u8 bit)
{
    bitmap_type *word = &bits[bit / BITS_PER_ULONG];
    (*word) &= ~(1 << (bit % BITS_PER_ULONG));
}

static inline void clear_bits(u8_bitmap *bits)
{
    memset(bits, 0, sizeof(u8_bitmap));
}

/* src/wifi_hal.c:3901-3903 */
u8_bitmap g_DialogToken[MAX_AP_INDEX] = {{0}};
/* Sending VAP index + 1 per originating VAP and dialog token (0 = not recorded). */
u8 g_DialogTokenSender[MAX_AP_INDEX][256] = { { 0 } };

extern "C" {
int hwr_wcb_lock_free(void) { if (pthread_mutex_trylock(&hwr_wcb_g.hapd_lock) != 0) return 0; pthread_mutex_unlock(&hwr_wcb_g.hapd_lock); return 1; }
void hwr_wcb_reset_tables(void) { memset(g_DialogToken, 0, sizeof(g_DialogToken)); memset(g_DialogTokenSender, 0, sizeof(g_DialogTokenSender)); }
void hwr_wcb_set_token(int vap, unsigned token) { set_bit_u8(g_DialogToken[vap], token); }
int hwr_wcb_get_token(int vap, unsigned token) { return get_bit_u8(g_DialogToken[vap], token); }
void hwr_wcb_set_sender(int orig_vap, unsigned token, int sent_vap) { g_DialogTokenSender[orig_vap][token] = (u8)(sent_vap + 1); }
int hwr_wcb_get_sender(int orig_vap, unsigned token) { return g_DialogTokenSender[orig_vap][token]; }
void hwr_wcb_tables(void **bitmaps, size_t *bitmaps_row, unsigned char **sender) { *bitmaps = g_DialogToken; *bitmaps_row = sizeof(g_DialogToken[0]); *sender = &g_DialogTokenSender[0][0]; }

/* --- wifi_hal.c:4090-4119 --- */
INT wifi_hal_cancelRMBeaconRequest(UINT apIndex, UCHAR dialogToken)
{
    UINT sent_vap_index = apIndex;
    UINT vap_index;

    // - verify input params
    if (_IS_INVALID_ARG(apIndex >= MAX_AP_INDEX)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    /* For MLO the request may have been sent on another link's VAP; clear the
     * bit on the VAP recorded by wifi_rrm_send_beacon_req(). */
    if (g_DialogTokenSender[apIndex][dialogToken] != 0) {
        sent_vap_index = g_DialogTokenSender[apIndex][dialogToken] - 1;
        g_DialogTokenSender[apIndex][dialogToken] = 0;
    }

    /* Keep the bit if another VAP's request with the same token was sent on it. */
    for (vap_index = 0; vap_index < MAX_AP_INDEX; vap_index++) {
        if (g_DialogTokenSender[vap_index][dialogToken] == sent_vap_index + 1) {
            break;
        }
    }
    if (vap_index == MAX_AP_INDEX) {
        reset_bit_u8(g_DialogToken[sent_vap_index], dialogToken);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return WIFI_HAL_SUCCESS;
}
}
