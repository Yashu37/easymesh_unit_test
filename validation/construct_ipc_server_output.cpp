/*
 * UNIT TEST (input constructor): construct_ipc_server_output
 *
 * ipc_server_output(desc, ...) is the server-side processor of the HAL IPC: it switches on
 * desc->type, calls the matching wifi_hal_* wrapper and copies the result into the descriptor /
 * a freshly malloc'd scratch buffer.  The 32 descriptor types are NOT all covered one by one
 * (the simple getters/setters only differ in the API they call); the cases here concentrate on the
 * types that handle memory: client scratch buffers, malloc'd arrays, array sizes and counts taken
 * from the client or returned by the API, plus error cleanup and unknown types (50 cases).
 *
 *  - every wifi_hal_* wrapper is a stub with a configurable return value / output (struct H);
 *    malloc / calloc / free go through counting stubs (leak check, failure injection by call number);
 *  - the "client scratch buffer" of a request is a real heap block (ASan red-zones around it);
 *  - the descriptor lives in the runner-owned hso_desc_slab, head and tail poisoned by the runner;
 *  - cases flagged `forked` are expected to crash the UNFIXED function (heap overflow / over-read /
 *    NULL dereference): the runner runs them in a child so the ASan report is visible but the run
 *    continues; the child must survive and return exp_ret once fixed.
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <stdarg.h>
#include <limits.h>
#include "hso_hal_ipc.h"

#define SZ  (sizeof(hal_ipc_processor_desc_t))

int  hso_outstanding;
char hso_log_buf[HSO_LOG_SZ];

static struct {
	int ret;                       /* returned by the simple wrapper stubs (0 = API ok) */
	int api_calls; const char *last_api;
	int mallocs, fail_at;          /* malloc/calloc call number that fails (1-based, 0 = never) */
	int sync_calls;
	int dwell_seen;
	int nb_count, nb_null;         /* wifi_hal_getNeighboringWiFiStatus result */
	unsigned stat_count;           /* rx / tx stats result count */
	int diag_count, diag_ret, diag_null;
	int str_mode;                  /* 0 empty, 1 "hso-name", 2 63 chars, 3 64 chars unterminated */
	unsigned assoc_len;
} H;

extern "C" {

void hso_print(int level, const char *format, ...)
{
	char tmp[1024]; va_list ap;
	(void)level;
	va_start(ap, format); vsnprintf(tmp, sizeof(tmp), format, ap); va_end(ap);
	snprintf(hso_log_buf, HSO_LOG_USE, "%s", tmp);              /* only the first HSO_LOG_USE bytes; the tail stays poisoned */
}

void *hso_malloc(size_t n)
{
	H.mallocs++;
	if (n >= (1u << 28) || (H.fail_at && H.mallocs == H.fail_at)) return NULL;
	hso_outstanding++;
	return malloc(n);
}
void *hso_calloc(size_t n, size_t m)
{
	H.mallocs++;
	if (n * m >= (1u << 28) || (H.fail_at && H.mallocs == H.fail_at)) return NULL;
	hso_outstanding++;
	return calloc(n, m);
}
void hso_free(void *p) { if (p) { hso_outstanding--; free(p); } }

int sync_hostapd_freq_param(unsigned int apIndex) { (void)apIndex; H.sync_calls++; return 0; }
char *to_mac_str(const mac_address_t mac, mac_addr_str_t key)
{
	snprintf(key, sizeof(mac_addr_str_t), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return key;
}

static int hso_diag_cb(int ap_index, wifi_associated_dev3_t *arr, unsigned int *n)
{
	(void)ap_index;
	*n = H.diag_count;
	for (int i = 0; i < H.diag_count && i < 16; i++) { memset(&arr[i], 0, sizeof(arr[i])); arr[i].cli_MACAddress[0] = (unsigned char)(i + 1); }
	return H.diag_ret;
}
app_get_ap_assoc_dev_diag_res3_t hso_get_diag_cb(void) { return H.diag_null ? NULL : hso_diag_cb; }

/* ---- wrappers with behaviour ---- */
INT wifi_hal_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *arr, INT n)
{
	(void)radioIndex; H.api_calls++;
	if (!H.ret) for (INT i = 0; i < n; i++) { memset(&arr[i], 0, sizeof(arr[i])); arr[i].ch_number = i + 1; }
	return H.ret;
}
INT wifi_hal_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *out) { (void)ssidIndex; H.api_calls++; memset(out, 0, sizeof(*out)); return H.ret; }

INT wifi_hal_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
	volatile unsigned sum = 0; (void)apIndex; (void)scan_mode;
	H.api_calls++; H.dwell_seen = dwell_time;
	for (UINT i = 0; i < chan_num; i++) sum += chan_list[i];     /* the real API reads chan_num entries of chan_list */
	return H.ret;
}
INT wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **arr, UINT *n)
{
	(void)radioIndex; H.api_calls++;
	if (H.ret) return H.ret;
	*n = H.nb_count;
	if (H.nb_null) { *arr = NULL; return 0; }
	*arr = (wifi_neighbor_ap2_t *)hso_malloc((H.nb_count ? H.nb_count : 1) * sizeof(wifi_neighbor_ap2_t));
	if (!*arr) return -1;
	for (int i = 0; i < H.nb_count; i++) { memset(&(*arr)[i], 0, sizeof(wifi_neighbor_ap2_t)); (*arr)[i].ap_Channel = i + 1; }
	return 0;
}
INT wifi_hal_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *mac, wifi_associated_dev_rate_info_rx_stats_t **arr, UINT *n, ULLONG *handle)
{
	(void)radioIndex; (void)mac; H.api_calls++;
	if (H.ret) return H.ret;
	*n = H.stat_count; *handle = 0x1234;
	for (unsigned i = 0; i < H.stat_count && i < 16; i++) memset(&(*arr)[i], (int)(i + 1), sizeof((*arr)[i]));   /* fills the 16 preallocated entries */
	return 0;
}
INT wifi_hal_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *mac, wifi_associated_dev_rate_info_tx_stats_t **arr, UINT *n, ULLONG *handle)
{
	(void)radioIndex; (void)mac; H.api_calls++;
	if (H.ret) return H.ret;
	*n = H.stat_count; *handle = 0x1234;
	for (unsigned i = 0; i < H.stat_count && i < 16; i++) memset(&(*arr)[i], (int)(i + 1), sizeof((*arr)[i]));
	return 0;
}
static void fill_str(CHAR *out)
{
	switch (H.str_mode) {
	case 1: strcpy(out, "hso-name"); break;
	case 2: memset(out, 'a', 63); out[63] = 0; break;
	case 3: memset(out, 'b', 64); break;               /* fills all 64 bytes, no terminator */
	default: break;                                      /* empty */
	}
}
INT wifi_hal_getSSIDNameStatus(INT apIndex, CHAR *out)             { (void)apIndex; H.api_calls++; if (!H.ret) fill_str(out); return H.ret; }
INT wifi_hal_getApName(INT apIndex, CHAR *out)                     { (void)apIndex; H.api_calls++; if (!H.ret) fill_str(out); return H.ret; }
INT wifi_hal_getSSIDName(INT apIndex, CHAR *out)                   { (void)apIndex; H.api_calls++; if (!H.ret) fill_str(out); return H.ret; }
INT wifi_hal_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *out) { (void)radioIndex; H.api_calls++; if (!H.ret) fill_str(out); return H.ret; }
INT wifi_hal_getRadioIfName(INT radioIndex, CHAR *out)             { (void)radioIndex; H.api_calls++; if (!H.ret) fill_str(out); return H.ret; }

INT wifi_hal_getAssociationReqIEs(UINT apIndex, const mac_address_t *mac, CHAR *req_ies, UINT req_ies_size, UINT *req_ies_len)
{
	static char pat[4096];
	(void)apIndex; (void)mac; H.api_calls++;
	memset(pat, 0x33, sizeof(pat));
	if (req_ies_size < H.assoc_len) return -1;                    /* as in the real wrapper: req_ies_size is the caller's capacity */
	memcpy(req_ies, pat, H.assoc_len);
	*req_ies_len = H.assoc_len;
	return 0;
}
INT wifi_hal_setNeighborReports(UINT apIndex, UINT num, wifi_NeighborReport_t *reports)
{
	volatile unsigned char sum = 0; (void)apIndex; H.api_calls++;
	for (size_t i = 0; i < num * sizeof(wifi_NeighborReport_t); i++) sum += ((unsigned char *)reports)[i];   /* the API reads num entries */
	return H.ret;
}
INT wifi_hal_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request) { (void)apIndex; (void)peerMac; (void)request; H.api_calls++; return H.ret; }
INT wifi_hal_setRMBeaconRequest(UINT apIndex, mac_address_t peer_mac, wifi_BeaconRequest_t *in_req, UCHAR *out_DialogToken) { (void)apIndex; (void)peer_mac; (void)in_req; *out_DialogToken = 7; H.api_calls++; return H.ret; }

/* ---- the remaining wrappers: return H.ret ---- */
INT wifi_hal_setRadioStatsEnable(INT radioIndex, BOOL enabled) { H.api_calls++; H.last_api = "wifi_hal_setRadioStatsEnable"; return H.ret; }
INT wifi_hal_getSSIDNumberOfEntries(ULONG *numEntries) { H.api_calls++; H.last_api = "wifi_hal_getSSIDNumberOfEntries"; return H.ret; }
INT wifi_hal_getApAssociatedDeviceStats(INT apIndex, mac_address_t *clientMacAddress, wifi_associated_dev_stats_t *associated_dev_stats, ULLONG *handle) { H.api_calls++; H.last_api = "wifi_hal_getApAssociatedDeviceStats"; return H.ret; }
INT wifi_hal_getSSIDEnable(INT ssidIndex, BOOL *output_bool) { H.api_calls++; H.last_api = "wifi_hal_getSSIDEnable"; return H.ret; }
INT wifi_hal_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex) { H.api_calls++; H.last_api = "wifi_hal_getSSIDRadioIndex"; return H.ret; }
INT wifi_hal_getNeighborReportActivation(UINT apIndex, BOOL *activate) { H.api_calls++; H.last_api = "wifi_hal_getNeighborReportActivation"; return H.ret; }
INT wifi_hal_getBSSTransitionActivation(UINT apIndex, BOOL *activate) { H.api_calls++; H.last_api = "wifi_hal_getBSSTransitionActivation"; return H.ret; }
INT wifi_hal_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn) { H.api_calls++; H.last_api = "wifi_hal_getApAssociatedClientDiagnosticResult"; return H.ret; }
INT wifi_hal_getRadioNumberOfEntries(ULONG *output) { H.api_calls++; H.last_api = "wifi_hal_getRadioNumberOfEntries"; return H.ret; }
INT wifi_hal_getMultiPskClientKey(INT apIndex, mac_address_t mac, wifi_key_multi_psk_t *key) { H.api_calls++; H.last_api = "wifi_hal_getMultiPskClientKey"; return H.ret; }
INT wifi_hal_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5) { H.api_calls++; H.last_api = "wifi_hal_steering_setGroup"; return H.ret; }
INT wifi_hal_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config) { H.api_calls++; H.last_api = "wifi_hal_steering_clientSet"; return H.ret; }
INT wifi_hal_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac) { H.api_calls++; H.last_api = "wifi_hal_steering_clientRemove"; return H.ret; }
INT wifi_hal_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason) { H.api_calls++; H.last_api = "wifi_hal_steering_clientDisconnect"; return H.ret; }
INT wifi_hal_getRadioCountryCode(INT radioIndex, CHAR *output_string) { H.api_calls++; H.last_api = "wifi_hal_getRadioCountryCode"; return H.ret; }
INT wifi_hal_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) { H.api_calls++; H.last_api = "wifi_hal_getRadioOperatingChannelBandwidth"; return H.ret; }
INT wifi_hal_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong) { H.api_calls++; H.last_api = "wifi_hal_getRadioTransmitPower"; return H.ret; }
INT wifi_hal_setNeighborReportActivation(UINT apIndex, BOOL activate) { H.api_calls++; H.last_api = "wifi_hal_setNeighborReportActivation"; return H.ret; }
INT wifi_hal_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong) { H.api_calls++; H.last_api = "wifi_hal_getApNumDevicesAssociated"; return H.ret; }

}  /* extern "C" */

/* ------------------------- request builders ------------------------- */
static void base(hal_ipc_processor_desc_t *d, int type, size_t client_scratch)
{
	memset(&H, 0, sizeof(H)); hso_outstanding = 0; hso_log_buf[0] = 0;
	memset(d, 0, SZ);
	d->type = (hal_ipc_desc_type_t)type;
	strcpy(d->name, "hso_test_req");
	d->len = SZ + client_scratch;
	d->scratch_buf_size = client_scratch;
	if (client_scratch) { d->scratch_buf = (unsigned char *)hso_malloc(client_scratch); memset(d->scratch_buf, 0x5A, client_scratch); }
	H.mallocs = 0;                                              /* injected failures count from the function's own allocations */
}
#define T(x) hal_ipc_desc_type_##x

static void chan(hal_ipc_processor_desc_t *d, int n, size_t scratch_elems)
{
	base(d, T(get_radio_chan_stats), scratch_elems * sizeof(wifi_channelStats_t));
	d->in.get_radio_channel_stats.radio_index = 0; d->in.get_radio_channel_stats.array_size = n;
}
static int v_chan(hal_ipc_processor_desc_t *d, int n)
{
	return d->len == SZ + n * sizeof(wifi_channelStats_t) && d->scratch_buf_size == n * sizeof(wifi_channelStats_t) &&
	       ((wifi_channelStats_t *)d->scratch_buf)[0].ch_number == 1 && ((wifi_channelStats_t *)d->scratch_buf)[n - 1].ch_number == (UINT)n;
}
static void scan(hal_ipc_processor_desc_t *d, int dwell, unsigned chan_num)
{
	base(d, T(start_neighbor_scan), 0);
	d->in.start_neighbor_scan.ap_index = 0; d->in.start_neighbor_scan.dwell_time = dwell; d->in.start_neighbor_scan.chan_num = chan_num;
}
static void nbst(hal_ipc_processor_desc_t *d, int count, int is_null) { base(d, T(get_neighbor_wifi_status), 0); H.nb_count = count; H.nb_null = is_null; }
static void rxst(hal_ipc_processor_desc_t *d, unsigned count) { base(d, T(get_ap_assoc_dev_rx_stats_result), 0); H.stat_count = count; }
static void txst(hal_ipc_processor_desc_t *d, unsigned count) { base(d, T(get_ap_assoc_dev_tx_stats_result), 0); H.stat_count = count; }
static void diag(hal_ipc_processor_desc_t *d, int count, int cb_ret, int cb_null) { base(d, T(get_ap_assoc_dev_diag_result3), 0); H.diag_count = count; H.diag_ret = cb_ret; H.diag_null = cb_null; }
static void nrep(hal_ipc_processor_desc_t *d, unsigned num, size_t scratch_elems)
{
	base(d, T(set_neighbor_reports), scratch_elems * sizeof(wifi_NeighborReport_t));
	d->in.set_neighbor_reports.ap_index = 0; d->in.set_neighbor_reports.num_neighbor_reports = num;
}
static void ies(hal_ipc_processor_desc_t *d, unsigned req_ies_size, unsigned assoc_len)
{
	base(d, T(get_association_req_ies), 0);
	d->in.get_association_req_ies.ap_index = 0; d->in.get_association_req_ies.req_ies_size = req_ies_size; H.assoc_len = assoc_len;
}

hso_case_t ipc_server_output_suite[] = {
	/* ---- get_radio_chan_stats: array_size from the client, scratch buffer in / out ---- */
	{ "chan_stats_array1_ok",           [](hal_ipc_processor_desc_t *d){ chan(d, 1, 1); },  [](hal_ipc_processor_desc_t *d, int) -> int { return v_chan(d, 1); },  0, 0 },
	{ "chan_stats_array64_ok",          [](hal_ipc_processor_desc_t *d){ chan(d, 64, 64); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_chan(d, 64); }, 0, 0 },
	{ "chan_stats_scratch_size_mismatch", [](hal_ipc_processor_desc_t *d){ chan(d, 4, 3); }, NULL, 0, -1 },
	{ "chan_stats_api_fails",           [](hal_ipc_processor_desc_t *d){ chan(d, 2, 2); H.ret = -1; }, NULL, 0, -1 },
	{ "chan_stats_output_malloc_fails", [](hal_ipc_processor_desc_t *d){ chan(d, 2, 2); H.fail_at = 2; }, NULL, 0, -1 },
	{ "chan_stats_array_size_negative", [](hal_ipc_processor_desc_t *d){ chan(d, -1, 0); }, NULL, 0, -1 },
	{ "crash_chan_stats_array_size_0",  [](hal_ipc_processor_desc_t *d){ chan(d, 0, 0); }, NULL, 1, -1 },
	/* ---- start_neighbor_scan: chan_num from the client, chan_list buffer ---- */
	{ "scan_chan_num_0_ok",             [](hal_ipc_processor_desc_t *d){ scan(d, 20, 0); }, NULL, 0, 0 },
	{ "scan_chan_num_1_ok",             [](hal_ipc_processor_desc_t *d){ scan(d, 20, 1); }, NULL, 0, 0 },
	{ "scan_dwell_0_defaults_to_5",     [](hal_ipc_processor_desc_t *d){ scan(d, 0, 1); }, [](hal_ipc_processor_desc_t *, int) -> int { return H.dwell_seen == 5; }, 0, 0 },
	{ "scan_api_fails",                 [](hal_ipc_processor_desc_t *d){ scan(d, 20, 1); H.ret = -1; }, NULL, 0, -1 },
	{ "crash_scan_chan_num_2",          [](hal_ipc_processor_desc_t *d){ scan(d, 20, 2); }, NULL, 1, 0 },
	{ "crash_scan_chan_num_64",         [](hal_ipc_processor_desc_t *d){ scan(d, 20, 64); }, NULL, 1, 0 },
	/* ---- get_neighbor_wifi_status: array returned by the API ---- */
	{ "neighbor_status_count1",         [](hal_ipc_processor_desc_t *d){ nbst(d, 1, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->scratch_buf_size == sizeof(wifi_neighbor_ap2_t) && d->len == SZ + sizeof(wifi_neighbor_ap2_t) && ((wifi_neighbor_ap2_t *)d->scratch_buf)[0].ap_Channel == 1; }, 0, 0 },
	{ "neighbor_status_count17_truncated", [](hal_ipc_processor_desc_t *d){ nbst(d, 17, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->scratch_buf_size == 16 * sizeof(wifi_neighbor_ap2_t); }, 0, 0 },
	{ "neighbor_status_empty_array",    [](hal_ipc_processor_desc_t *d){ nbst(d, 0, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->len == SZ; }, 0, 0 },
	{ "neighbor_status_null_array",     [](hal_ipc_processor_desc_t *d){ nbst(d, 3, 1); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->len == SZ; }, 0, 0 },
	{ "neighbor_status_api_fails",      [](hal_ipc_processor_desc_t *d){ nbst(d, 2, 0); H.ret = -1; }, NULL, 0, -1 },
	{ "neighbor_status_scratch_malloc_fails", [](hal_ipc_processor_desc_t *d){ nbst(d, 2, 0); H.fail_at = 2; }, NULL, 0, -1 },
	/* ---- get_ap_assoc_dev_rx_stats_result ---- */
	{ "rx_stats_count1",                [](hal_ipc_processor_desc_t *d){ rxst(d, 1); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->out.get_ap_assoc_dev_rx_stats_result.output_array_size == 1 && d->scratch_buf_size == sizeof(wifi_associated_dev_rate_info_rx_stats_t); }, 0, 0 },
	{ "rx_stats_count17_truncated", [](hal_ipc_processor_desc_t *d){ rxst(d, 17); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->scratch_buf_size == 16 * sizeof(wifi_associated_dev_rate_info_rx_stats_t) && d->out.get_ap_assoc_dev_rx_stats_result.output_array_size == 16; }, 0, 0 },
	{ "rx_stats_count0_empty",          [](hal_ipc_processor_desc_t *d){ rxst(d, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->len == SZ; }, 0, 0 },
	{ "rx_stats_api_fails",             [](hal_ipc_processor_desc_t *d){ rxst(d, 2); H.ret = -1; }, NULL, 0, -1 },
	{ "rx_stats_prealloc_malloc_fails", [](hal_ipc_processor_desc_t *d){ rxst(d, 2); H.fail_at = 1; }, NULL, 0, -1 },
	/* ---- get_ap_assoc_dev_tx_stats_result ---- */
	{ "tx_stats_count1",                [](hal_ipc_processor_desc_t *d){ txst(d, 1); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->out.get_ap_assoc_dev_tx_stats_result.output_array_size == 1 && d->scratch_buf_size == sizeof(wifi_associated_dev_rate_info_tx_stats_t); }, 0, 0 },
	{ "tx_stats_count17_truncated",     [](hal_ipc_processor_desc_t *d){ txst(d, 17); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->scratch_buf_size == 16 * sizeof(wifi_associated_dev_rate_info_tx_stats_t) && d->out.get_ap_assoc_dev_tx_stats_result.output_array_size == 16; }, 0, 0 },
	{ "tx_stats_api_fails",             [](hal_ipc_processor_desc_t *d){ txst(d, 2); H.ret = -1; }, NULL, 0, -1 },
	{ "crash_tx_stats_output_malloc_fails", [](hal_ipc_processor_desc_t *d){ txst(d, 2); H.fail_at = 2; }, NULL, 1, -1 },
	/* ---- get_ap_assoc_dev_diag_result3: monitor callback fills a 16-entry array ---- */
	{ "diag3_callback_null",            [](hal_ipc_processor_desc_t *d){ diag(d, 1, 0, 1); }, NULL, 0, -1 },
	{ "diag3_count0_ok",                [](hal_ipc_processor_desc_t *d){ diag(d, 0, 0, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->out.get_ap_assoc_dev_diag_result3.num == 0 && d->len == SZ; }, 0, 0 },
	{ "diag3_count0_callback_fails",    [](hal_ipc_processor_desc_t *d){ diag(d, 0, -1, 0); }, NULL, 0, -1 },
	{ "diag3_count1",                   [](hal_ipc_processor_desc_t *d){ diag(d, 1, 0, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->scratch_buf_size == sizeof(wifi_associated_dev3_t) && ((wifi_associated_dev3_t *)d->scratch_buf)[0].cli_MACAddress[0] == 1; }, 0, 0 },
	{ "diag3_callback_fails_count3",    [](hal_ipc_processor_desc_t *d){ diag(d, 3, -1, 0); }, NULL, 0, -1 },
	{ "diag3_array_malloc_fails",       [](hal_ipc_processor_desc_t *d){ diag(d, 2, 0, 0); H.fail_at = 1; }, NULL, 0, -1 },
	{ "crash_diag3_count17",            [](hal_ipc_processor_desc_t *d){ diag(d, 17, 0, 0); }, NULL, 1, 0 },
	/* ---- set_neighbor_reports: scratch_buf_size / num from the client, 16-entry destination ---- */
	{ "neighbor_reports_n1_ok",         [](hal_ipc_processor_desc_t *d){ nrep(d, 1, 1); }, NULL, 0, 0 },
	{ "neighbor_reports_n16_ok",        [](hal_ipc_processor_desc_t *d){ nrep(d, 16, 16); }, NULL, 0, 0 },
	{ "neighbor_reports_api_fails",     [](hal_ipc_processor_desc_t *d){ nrep(d, 2, 2); H.ret = -1; }, NULL, 0, -1 },
	{ "crash_neighbor_reports_n17",     [](hal_ipc_processor_desc_t *d){ nrep(d, 17, 17); }, NULL, 1, -1 },
	{ "crash_neighbor_reports_scratch20_n1", [](hal_ipc_processor_desc_t *d){ nrep(d, 1, 20); }, NULL, 1, -1 },
	/* ---- get_association_req_ies: req_ies_size from the client vs the 1024-byte buffer ---- */
	{ "assoc_ies_size1024_len50_ok",    [](hal_ipc_processor_desc_t *d){ ies(d, 1024, 50); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->out.get_association_req_ies.req_ies_len == 50; }, 0, 0 },
	{ "assoc_ies_size1024_len1024_ok",  [](hal_ipc_processor_desc_t *d){ ies(d, 1024, 1024); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->out.get_association_req_ies.req_ies_len == 1024; }, 0, 0 },
	{ "assoc_ies_size10_len50_api_error", [](hal_ipc_processor_desc_t *d){ ies(d, 10, 50); }, NULL, 0, -1 },
	{ "crash_assoc_ies_size5000_len2000", [](hal_ipc_processor_desc_t *d){ ies(d, 5000, 2000); }, NULL, 1, -1 },
	/* ---- string getters ---- */
	{ "ssid_name_ok",                   [](hal_ipc_processor_desc_t *d){ base(d, T(get_ssid_name), 0); H.str_mode = 1; }, [](hal_ipc_processor_desc_t *d, int) -> int { return !strcmp(d->out.get_ssid_name.output_string, "hso-name"); }, 0, 0 },
	{ "ap_name_ok",                     [](hal_ipc_processor_desc_t *d){ base(d, T(get_ap_name), 0); H.str_mode = 1; }, [](hal_ipc_processor_desc_t *d, int) -> int { return !strcmp(d->out.get_ap_name.output_string, "hso-name"); }, 0, 0 },
	{ "radio_if_name_63_chars_ok",      [](hal_ipc_processor_desc_t *d){ base(d, T(get_radio_if_name), 0); H.str_mode = 2; }, [](hal_ipc_processor_desc_t *d, int) -> int { return strlen(d->out.get_radio_if_name.output_string) == 63; }, 0, 0 },
	{ "ssid_name_empty_rejected",       [](hal_ipc_processor_desc_t *d){ base(d, T(get_ssid_name), 0); H.str_mode = 0; }, NULL, 0, -1 },
	/* ---- unknown descriptor type ---- */
	{ "unknown_type_99",                [](hal_ipc_processor_desc_t *d){ base(d, 99, 0); }, NULL, 0, -1 },
	{ "type_max_rejected",              [](hal_ipc_processor_desc_t *d){ base(d, hal_ipc_desc_type_max, 0); }, NULL, 0, -1 },
	{ NULL, NULL, NULL, 0, 0 }
};
