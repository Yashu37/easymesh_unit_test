/*
 * HANDLER: wifi_hal_getNeighboringWiFiStatus / wifi_hal_getNeighboringWiFiStatus_test (src/wifi_hal.c)
 *
 * Functions copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:3587-3704 (~/Desktop/G/rdk-wifi-hal): the static worker _wifi_hal_getNeighboringWiFiStatus (3587-3689) and its two public wrappers
 * (3691-3694 normal API, 3696-3703 test mode), generic build (OPTION_GET_CHANNELS_FROM_HOSTAP is 1, so the private VAP interface is used).  This file holds the ORIGINAL code (no fixes).  The worker checks
 * the pointers and the radio index, finds the radio and its private interface, and under scan_state_mutex reports an aborted / failed / not triggered / running scan, or (when results are available) copies
 * them with copy_scan_results under scan_info_ap_mutex and clears the results flag (the API flag, or the TEST flag in test mode when the scan is still running).
 *
 * Scaffolding only: get_radio_by_rdk_index / get_private_vap_interface / copy_scan_results are stubs over the runner's world (copy_scan_results is a separate static function, 3078, and is stubbed: it
 * writes a marker array and size when the configured result is 0); pthread mutexes are real; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_getNeighboringWiFiStatus[_test].
 */
#include "hwr_wnw.h"
#include <stdio.h>
#include <string.h>

#define OPTION_GET_CHANNELS_FROM_HOSTAP 1
#define wifi_hal_stats_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_stats_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define get_radio_by_rdk_index hwr_wnw_get_radio_by_rdk_index
#define get_primary_interface hwr_wnw_get_private_vap_interface
#define get_private_vap_interface hwr_wnw_get_private_vap_interface
#define copy_scan_results hwr_wnw_copy_scan_results
#define wifi_hal_getNeighboringWiFiStatus_test hwr_sg_wifi_hal_getNeighboringWiFiStatus_test
#define wifi_hal_getNeighboringWiFiStatus hwr_sg_wifi_hal_getNeighboringWiFiStatus

/* src/wifi_hal.c:62-94 (non-emulator variant) */
#define RADIO_INDEX_ASSERT_RC(radioIndex, retcode) \
    do { \
        int _index = (int)radioIndex; \
        if ((_index >= (MAX_NUM_RADIOS)) || (_index < 0)) { \
            wifi_hal_stats_error_print("%s: INCORRECT radioIndex = %d numRadios = %d\n", \
                    __FUNCTION__, _index, MAX_NUM_RADIOS); \
            return retcode; \
        } \
    } while (0)
#define RADIO_INDEX_ASSERT(radioIndex)  RADIO_INDEX_ASSERT_RC(radioIndex, WIFI_HAL_INVALID_ARGUMENTS)

hwr_wnw_world_t hwr_wnw_world;
wifi_neighbor_ap2_t hwr_wnw_marker;

static wifi_radio_info_t *get_radio_by_rdk_index(int index)
{
    if (hwr_wnw_world.no_radio || index < 0 || index >= HWR_WNW_MAXR) return NULL;
    return &hwr_wnw_world.radios[index];
}
static wifi_interface_info_t *get_private_vap_interface(wifi_radio_info_t *radio)
{
    hwr_wnw_world.private_calls++;
    return hwr_wnw_world.no_iface ? NULL : &hwr_wnw_world.ifs[radio->index];
}
static int copy_scan_results(wifi_interface_info_t *interface, wifi_neighbor_ap2_t **ap_array, unsigned int *array_size)
{
    hwr_wnw_world.copy_calls++; hwr_wnw_world.copy_iface = interface;
    /* the worker holds scan_state_mutex (busy) and scan_info_ap_mutex (busy) here */
    hwr_wnw_world.mutex_ok_at_copy = pthread_mutex_trylock(&interface->scan_state_mutex) != 0 && pthread_mutex_trylock(&interface->scan_info_ap_mutex) != 0;
    if (hwr_wnw_world.copy_ret != 0) return hwr_wnw_world.copy_ret;
    *ap_array = &hwr_wnw_marker; *array_size = HWR_WNW_MARK_SIZE;
    return 0;
}

extern "C" {
/* --- wifi_hal.c:3587-3704 --- */
static INT _wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size, bool test_mode)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    int ret;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] == ENTER ==\n", __func__, __LINE__);

    if (!neighbor_ap_array || !output_array_size) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Invalid parameters\n", __func__, __LINE__);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    RADIO_INDEX_ASSERT(radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] radio for radio index:%d not found\n", __func__, __LINE__, radioIndex);
        return WIFI_HAL_ERROR;
    }

#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] primary interface for radio '%s' not found\n", __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#else
    interface = get_private_vap_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] private interface for radio '%s' not found\n", __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#endif

    pthread_mutex_lock(&interface->scan_state_mutex);

    if (interface->scan_state == WIFI_SCAN_STATE_ABORTED) {
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Scan was aborted\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (interface->scan_state == WIFI_SCAN_STATE_ERROR) {
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Error happened during scan\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    /* If API scan results are available, return them regardless of scan_state */
    if (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_API)
        goto get_results;

    /* In test mode: If TEST scan results are available, return them regardless of scan_state */
    if (test_mode && (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_TEST))
        goto get_results;

    if (interface->scan_state == WIFI_SCAN_STATE_NONE) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan was not triggered\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (interface->scan_state == WIFI_SCAN_STATE_STARTED) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan is running, come later\n", __func__, __LINE__);
        errno = EAGAIN;
        return WIFI_HAL_NOT_READY;
    }

get_results:
    if (interface->scan_state == WIFI_SCAN_STATE_STARTED)
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan is running, but previous scan results are available\n", __func__, __LINE__);
    else
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan results are available\n", __func__, __LINE__);

    pthread_mutex_lock(&interface->scan_info_ap_mutex);
    ret = copy_scan_results(interface, neighbor_ap_array, output_array_size);
    pthread_mutex_unlock(&interface->scan_info_ap_mutex);
    if (ret != RETURN_OK) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] copy_scan_results returned with error\n", __func__, __LINE__);
    }

    if (test_mode) {
        // - test mode: reset results only if scan is in progress;
        if (interface->scan_state == WIFI_SCAN_STATE_STARTED)
            interface->scan_has_results &= ~WIFI_SCAN_RES_COLLECTED_TEST;
    }
    else {
        // - reset results for normal API call
        interface->scan_has_results &= ~WIFI_SCAN_RES_COLLECTED_API;
    }

    pthread_mutex_unlock(&interface->scan_state_mutex);

    if (ret != RETURN_OK)
        return WIFI_HAL_ERROR;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] SCAN results are ready | output_array_size:%d\n", __func__, __LINE__, *output_array_size);
    return WIFI_HAL_SUCCESS;
}

INT wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return _wifi_hal_getNeighboringWiFiStatus(radioIndex, neighbor_ap_array, output_array_size, false);
}

/*
  - Special internal version of the wifi_hal_getNeighboringWiFiStatus() function for test purposes.
    This API does not clear the results of a previous scan and returns a filled table until a new scan is started.
    Needed by the wifi_api2 tool to avoid races with the OneWifi process.
*/
INT wifi_hal_getNeighboringWiFiStatus_test(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return _wifi_hal_getNeighboringWiFiStatus(radioIndex, neighbor_ap_array, output_array_size, true);
}
}
