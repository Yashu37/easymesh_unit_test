/*
 * UNIT TEST (input constructor): construct_get_processor_desc
 *
 * get_processor_desc() takes ONE parameter, the descriptor type, and returns
 * &processor_desc[type] with no range check.  The input space is the type
 * value: every valid enum value (0 .. hal_ipc_desc_type_max-1) and a set of
 * invalid / edge values (negative, == max, > max, huge, INT_MIN/INT_MAX),
 * each checked several ways:
 *   valid   : returned pointer == &table[t]; name matches the real table
 *             entry; desc->type == t; pointer lies inside the table;
 *             adjacent entries are exactly sizeof(desc) apart.
 *   invalid : returns NULL; contract check "NULL or inside the table"; and a
 *             dereference (when non-NULL), which must not crash (run in-process
 *             and last, so without FIX 1 the run aborts with the ASan report).  Before FIX 1 every invalid case failed (no bounds check
 *             on `type`, pointer outside processor_desc[], ASan
 *             global-buffer-overflow on use); with FIX 1 all pass.
 * Expected result is the SAFE contract (1 = ok), so a FAIL is a finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "common.h"

char gpd_name_buf[GPD_NAME_SZ];

const char *gpd_expected_names[] = {
	"wifi_setRadioStatsEnable",
	"wifi_getSSIDNumberOfEntries",
	"wifi_getApAssociatedDeviceStats",
	"wifi_getRadioChannelStats",
	"wifi_startNeighborScan",
	"wifi_getNeighboringWiFiStatus",
	"wifi_getSSIDTrafficStats2",
	"wifi_getApAssociatedDeviceRxStatsResult",
	"wifi_getSSIDEnable",
	"wifi_getSSIDRadioIndex",
	"wifi_getSSIDNameStatus",
	"wifi_getApName",
	"wifi_getNeighborReportActivation",
	"wifi_getBSSTransitionActivation",
	"wifi_getApAssociatedDeviceDiagnosticResult3",
	"wifi_getApAssociatedClientDiagnosticResult",
	"wifi_getRadioOperatingFrequencyBand",
	"wifi_getRadioNumberOfEntries",
	"wifi_getApAssociatedDeviceTxStatsResult",
	"wifi_steering_setGroup",
	"wifi_steering_clientSet",
	"wifi_steering_clientRemove",
	"wifi_steering_clientDisconnect",
	"wifi_setBTMRequest",
	"wifi_getSSIDName",
	"wifi_setRMBeaconRequest",
	"wifi_getAssociationReqIEs",
	"wifi_setNeighborReports",
	"wifi_setNeighborReportActivation",
	"wifi_getRadioIfName",
	"wifi_getApNumDevicesAssociated",
	"wifi_steering_eventUnregister",
	"wifi_steering_eventRegister",
	"steering event notification",
	"wifi_mgmt_frame_callbacks_register",
	"mgmt frame event notification",
	"wifi_RMBeaconRequestCallbackRegister",
	"RM beacon report event notification",
	"wifi_BTMQueryRequest_callback_register",
	"BTM query request event notification",
	"BTM response event notification",
	NULL
};

gpd_test_case_t get_processor_desc_suite[] = {
	{ "valid_t00_ptr_eq_set_radio_stats_enable", 0, 0, 1 },
	{ "valid_t00_name_set_radio_stats_enable", 0, 1, 1 },
	{ "valid_t00_typefield_set_radio_stats_enable", 0, 2, 1 },
	{ "valid_t00_in_range_set_radio_stats_enable", 0, 3, 1 },
	{ "valid_t01_ptr_eq_get_ssid_num_of_entries", 1, 0, 1 },
	{ "valid_t01_name_get_ssid_num_of_entries", 1, 1, 1 },
	{ "valid_t01_typefield_get_ssid_num_of_entries", 1, 2, 1 },
	{ "valid_t01_in_range_get_ssid_num_of_entries", 1, 3, 1 },
	{ "valid_t20_ptr_eq_steering_client_set", 20, 0, 1 },
	{ "valid_t20_name_steering_client_set", 20, 1, 1 },
	{ "valid_t20_typefield_steering_client_set", 20, 2, 1 },
	{ "valid_t20_in_range_steering_client_set", 20, 3, 1 },
	{ "valid_t39_ptr_eq_btm_query_request_event", 39, 0, 1 },
	{ "valid_t39_name_btm_query_request_event", 39, 1, 1 },
	{ "valid_t39_typefield_btm_query_request_event", 39, 2, 1 },
	{ "valid_t39_in_range_btm_query_request_event", 39, 3, 1 },
	{ "valid_t40_ptr_eq_btm_response_event", 40, 0, 1 },
	{ "valid_t40_name_btm_response_event", 40, 1, 1 },
	{ "valid_t40_typefield_btm_response_event", 40, 2, 1 },
	{ "valid_t40_in_range_btm_response_event", 40, 3, 1 },
	{ "valid_t00_stride_to_next", 0, 4, 1 },
	{ "valid_t20_stride_to_next", 20, 4, 1 },
	{ "valid_t39_stride_to_next", 39, 4, 1 },
	{ "invalid_neg1_returns_null", -1, 5, 1 },
	{ "invalid_neg1_returns_null_or_in_table", -1, 6, 1 },
	{ "invalid_neg2147483648_returns_null", -2147483648, 5, 1 },
	{ "invalid_neg2147483648_returns_null_or_in_table", -2147483648, 6, 1 },
	{ "invalid_pos41_returns_null", 41, 5, 1 },
	{ "invalid_pos41_returns_null_or_in_table", 41, 6, 1 },
	{ "invalid_pos42_returns_null", 42, 5, 1 },
	{ "invalid_pos42_returns_null_or_in_table", 42, 6, 1 },
	{ "invalid_pos1000_returns_null", 1000, 5, 1 },
	{ "invalid_pos1000_returns_null_or_in_table", 1000, 6, 1 },
	{ "invalid_pos2147483647_returns_null", 2147483647, 5, 1 },
	{ "invalid_pos2147483647_returns_null_or_in_table", 2147483647, 6, 1 },
	/* crash cases last: without FIX 1 the first of these aborts under ASan */
	{ "invalid_pos41_deref_does_not_crash", 41, 7, 1 },
	{ "invalid_neg1_deref_does_not_crash", -1, 7, 1 },
	{ "invalid_neg2147483648_deref_does_not_crash", -2147483648, 7, 1 },
	{ "invalid_pos42_deref_does_not_crash", 42, 7, 1 },
	{ "invalid_pos1000_deref_does_not_crash", 1000, 7, 1 },
	{ "invalid_pos2147483647_deref_does_not_crash", 2147483647, 7, 1 },
	{ NULL, 0, 0, 0 }
};

static const gpd_test_case_t *cur_tc;

void construct_get_processor_desc_input(const gpd_test_case_t *tc)
{
	cur_tc = tc;
	memset(gpd_name_buf, 0, GPD_NAME_SZ);
}

static int in_table(const void *p)
{
	return (const char *)p >= (const char *)&processor_desc[0] &&
	       (const char *)p <  (const char *)&processor_desc[hal_ipc_desc_type_max];
}

static int deref_in_child(hal_ipc_processor_desc_t *d)
{
	/* What every real caller does: use desc->... (a correct caller checks NULL first).
	 * Run in-process: without FIX 1 this is the ASan abort. */
	if (d != NULL) {
		volatile int sink = d->type;
		(void)sink;
	}
	return 1;                                     /* reached = did not crash */
}

int get_processor_desc_run_current(void)
{
	hal_ipc_desc_type_t t = (hal_ipc_desc_type_t)cur_tc->type_value;
	hal_ipc_processor_desc_t *d = get_processor_desc(t);

	switch (cur_tc->kind) {
	case GPD_PTR_EQ:
		return d == &processor_desc[cur_tc->type_value];
	case GPD_NAME:
		strncpy(gpd_name_buf, d->name, GPD_NAME_USE - 1);   /* runner-owned copy, tail poisoned */
		return !strcmp(gpd_name_buf, gpd_expected_names[cur_tc->type_value]);
	case GPD_TYPEFIELD:
		return d->type == t;
	case GPD_IN_RANGE:
		return d != NULL && in_table(d);
	case GPD_STRIDE: {
		hal_ipc_processor_desc_t *n = get_processor_desc((hal_ipc_desc_type_t)(cur_tc->type_value + 1));
		return (size_t)((char *)n - (char *)d) == sizeof(hal_ipc_processor_desc_t);
	}
	case GPD_PTR_ARITH:                               /* invalid type -> NULL (was: unchecked arithmetic before FIX 1) */
		return d == NULL;
	case GPD_SAFE_RANGE:
		return d == NULL || in_table(d);
	case GPD_DEREF_NO_CRASH:
		return deref_in_child(d);
	}
	return 0;
}
