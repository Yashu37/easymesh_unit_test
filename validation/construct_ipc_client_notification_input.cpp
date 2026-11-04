/*
 * UNIT TEST (input constructor): construct_ipc_client_notification_input
 *
 * ipc_client_notification_input(desc, arg1..arg5) packs the arguments of a HAL notification
 * (steering event, RM beacon report, BTM query, BTM response) into the descriptor / a malloc'd
 * scratch buffer before it is sent to the server.  Each event type takes a different set of
 * arguments (void *), copies fixed-size structs from them, and rejects NULL ones.
 *
 * The arguments live in runner-owned slabs hcn_arg_slab[i] (the bytes past each argument's valid
 * length are poisoned by the runner, so over-reads are caught); the descriptor starts with
 * len = 0 as in the processor_desc[] table.  Inputs crossed: the 4 event types x (valid, each argument
 * NULL, malloc failure), boundary values, the BTM peer MAC string (valid, upper-case, malformed, short,
 * empty, 17 characters without a NUL), mgmt_frame_event, unknown / non-notification types and a NULL
 * descriptor.  Cases that crash the unfixed function run forked (visible ASan report).
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <stdarg.h>
#include <limits.h>
#include "hcn_defs.h"

unsigned char hcn_desc_slab[sizeof(hal_ipc_processor_desc_t) + 2 * HCN_PAD];
unsigned char hcn_arg_slab[5][HCN_ARG_SZ];
size_t        hcn_arg_len[5];
char          hcn_log_buf[HCN_LOG_SZ];
int           hcn_outstanding;

#define SZ  (sizeof(hal_ipc_processor_desc_t))
static struct { int mallocs, fail_at; } H;

extern "C" {
void hcn_print(int level, const char *format, ...)
{
	char tmp[1024]; va_list ap;
	(void)level;
	va_start(ap, format); vsnprintf(tmp, sizeof(tmp), format, ap); va_end(ap);
	snprintf(hcn_log_buf, HCN_LOG_USE, "%s", tmp);
}
void *hcn_malloc(size_t n)
{
	H.mallocs++;
	if (n >= (1u << 28) || (H.fail_at && H.mallocs == H.fail_at)) return NULL;
	hcn_outstanding++;
	return malloc(n);
}
void hcn_free(void *p) { if (p) { hcn_outstanding--; free(p); } }
}

static unsigned char pat(size_t i, int seed) { return (unsigned char)(i * 7 + seed); }

/* copy `len` pattern bytes into argument slab i and hand its address out */
static void put(hcn_req_t *r, int i, size_t len, int seed)
{
	for (size_t k = 0; k < len; k++) hcn_arg_slab[i][k] = pat(k, seed);
	hcn_arg_len[i] = len; r->a[i] = hcn_arg_slab[i];
}
static void put_uint(hcn_req_t *r, int i, unsigned v) { memcpy(hcn_arg_slab[i], &v, sizeof(v)); hcn_arg_len[i] = sizeof(v); r->a[i] = hcn_arg_slab[i]; }
static void put_uchar(hcn_req_t *r, int i, unsigned char v) { hcn_arg_slab[i][0] = v; hcn_arg_len[i] = 1; r->a[i] = hcn_arg_slab[i]; }
static void put_str(hcn_req_t *r, int i, const char *s, int terminate)
{
	size_t n = strlen(s);
	memcpy(hcn_arg_slab[i], s, n);
	if (terminate) hcn_arg_slab[i][n++] = 0;
	hcn_arg_len[i] = n; r->a[i] = hcn_arg_slab[i];
}

static void base(hcn_req_t *r, int type)
{
	memset(&H, 0, sizeof(H)); hcn_outstanding = 0; hcn_log_buf[0] = 0;
	memset(r->d, 0, SZ);
	r->d->type = (hal_ipc_desc_type_t)type;
	strcpy(r->d->name, "hcn_test_event");
	r->d->len = 0;                                           /* processor_desc[] table initial value */
	for (int i = 0; i < 5; i++) { r->a[i] = NULL; hcn_arg_len[i] = 0; }
}
#define T(x) hal_ipc_desc_type_##x

/* ---- builders: all arguments valid, optionally one NULL (skip = 1..5) ---- */
static void se(hcn_req_t *r, int skip)
{
	base(r, T(steering_event));
	if (skip != 1) put_uint(r, 0, 7); if (skip != 2) put(r, 1, sizeof(wifi_steering_event_t), 1);
}
static void rm(hcn_req_t *r, int skip)
{
	base(r, hal_ipc_rm_beacon_report_event) ;
	if (skip != 1) put_uint(r, 0, 3); if (skip != 2) put(r, 1, sizeof(wifi_BeaconReport_t), 2);
	if (skip != 3) put_uint(r, 2, 5); if (skip != 4) put_uchar(r, 3, 9);
}
static void bq(hcn_req_t *r, int skip)
{
	base(r, hal_ipc_btm_query_request_event);
	if (skip != 1) put_uint(r, 0, 4); if (skip != 2) put(r, 1, sizeof(mac_address_t), 3);
	if (skip != 3) put(r, 2, sizeof(wifi_BTMQuery_t), 4); if (skip != 4) put_uint(r, 3, 1234);
	if (skip != 5) put(r, 4, sizeof(wifi_BTMRequest_t), 5);
}
static void br(hcn_req_t *r, int skip, const char *mac, int terminate)
{
	base(r, hal_ipc_btm_response_event);
	if (skip != 1) put_uint(r, 0, 2); if (skip != 2) put_str(r, 1, mac, terminate);
	if (skip != 3) put(r, 2, sizeof(wifi_BTMResponse_t), 6);
}

/* ---- verifiers ---- */
static int v_se(hal_ipc_processor_desc_t *d, int)
{
	unsigned g; memcpy(&g, hcn_arg_slab[0], 4);
	return d->in.steering_event_data.steering_group_index == g &&
	       !memcmp(&d->in.steering_event_data.evt, hcn_arg_slab[1], sizeof(wifi_steering_event_t)) && d->len == SZ;
}
static int v_rm(hal_ipc_processor_desc_t *d, int)
{
	return d->in.rm_beacon_report_event_data.apIndex == 3 && d->in.rm_beacon_report_event_data.out_array_size == 5 &&
	       d->in.rm_beacon_report_event_data.out_DialogToken == 9 && d->scratch_buf_size == sizeof(wifi_BeaconReport_t) &&
	       d->len == SZ + sizeof(wifi_BeaconReport_t) && !memcmp(d->scratch_buf, hcn_arg_slab[1], sizeof(wifi_BeaconReport_t));
}
static int v_bq(hal_ipc_processor_desc_t *d, int)
{
	size_t q = sizeof(wifi_BTMQuery_t), rq = sizeof(wifi_BTMRequest_t);
	return d->in.btm_query_request_event_data.apIndex == 4 && d->in.btm_query_request_event_data.inMemSize == 1234 &&
	       !memcmp(d->in.btm_query_request_event_data.peerMac, hcn_arg_slab[1], sizeof(mac_address_t)) &&
	       d->scratch_buf_size == q + rq && d->len == SZ + q + rq &&
	       !memcmp(d->scratch_buf, hcn_arg_slab[2], q) && !memcmp(d->scratch_buf + q, hcn_arg_slab[4], rq);
}
static int v_br_common(hal_ipc_processor_desc_t *d, const unsigned char *mac)
{
	return d->in.btm_response_event_data.apIndex == 2 && !memcmp(d->in.btm_response_event_data.peerMac, mac, 6) &&
	       !memcmp(&d->in.btm_response_event_data.response, hcn_arg_slab[2], sizeof(wifi_BTMResponse_t));
}
static const unsigned char MAC1[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const unsigned char MAC2[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

hcn_case_t ipc_client_notification_input_suite[] = {
	/* ---- steering_event (2 args) ---- */
	{ "steering_event_ok",                 [](hcn_req_t *r){ se(r, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_se(d, 0); }, 0, 0 },
	{ "steering_event_arg1_null",          [](hcn_req_t *r){ se(r, 1); }, NULL, 0, -1 },
	{ "steering_event_arg2_null",          [](hcn_req_t *r){ se(r, 2); }, NULL, 0, -1 },
	{ "steering_event_both_null",          [](hcn_req_t *r){ se(r, 1); r->a[1] = NULL; }, NULL, 0, -1 },
	{ "steering_event_group_uint_max",     [](hcn_req_t *r){ se(r, 0); put_uint(r, 0, UINT_MAX); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->in.steering_event_data.steering_group_index == UINT_MAX; }, 0, 0 },
	/* ---- rm_beacon_report_event (4 args, malloc'd scratch) ---- */
	{ "rm_beacon_ok",                      [](hcn_req_t *r){ rm(r, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_rm(d, 0); }, 0, 0 },
	{ "rm_beacon_arg1_null",               [](hcn_req_t *r){ rm(r, 1); }, NULL, 0, -1 },
	{ "rm_beacon_arg2_null",               [](hcn_req_t *r){ rm(r, 2); }, NULL, 0, -1 },
	{ "rm_beacon_arg3_null",               [](hcn_req_t *r){ rm(r, 3); }, NULL, 0, -1 },
	{ "rm_beacon_arg4_null",               [](hcn_req_t *r){ rm(r, 4); }, NULL, 0, -1 },
	{ "rm_beacon_malloc_fails",            [](hcn_req_t *r){ rm(r, 0); H.fail_at = 1; }, NULL, 0, -1 },
	{ "rm_beacon_boundary_values",         [](hcn_req_t *r){ rm(r, 0); put_uint(r, 0, UINT_MAX); put_uint(r, 2, UINT_MAX); put_uchar(r, 3, 255); },
	                                       [](hal_ipc_processor_desc_t *d, int) -> int { return d->in.rm_beacon_report_event_data.out_array_size == UINT_MAX && d->in.rm_beacon_report_event_data.out_DialogToken == 255; }, 0, 0 },
	{ "rm_beacon_zero_values",             [](hcn_req_t *r){ rm(r, 0); put_uint(r, 0, 0); put_uint(r, 2, 0); put_uchar(r, 3, 0); },
	                                       [](hal_ipc_processor_desc_t *d, int) -> int { return d->in.rm_beacon_report_event_data.apIndex == 0 && d->len == SZ + sizeof(wifi_BeaconReport_t); }, 0, 0 },
	/* ---- btm_query_request_event (5 args, malloc'd scratch) ---- */
	{ "btm_query_ok",                      [](hcn_req_t *r){ bq(r, 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_bq(d, 0); }, 0, 0 },
	{ "btm_query_arg1_null",               [](hcn_req_t *r){ bq(r, 1); }, NULL, 0, -1 },
	{ "btm_query_arg2_null",               [](hcn_req_t *r){ bq(r, 2); }, NULL, 0, -1 },
	{ "btm_query_arg3_null",               [](hcn_req_t *r){ bq(r, 3); }, NULL, 0, -1 },
	{ "btm_query_arg4_null",               [](hcn_req_t *r){ bq(r, 4); }, NULL, 0, -1 },
	{ "btm_query_malloc_fails",            [](hcn_req_t *r){ bq(r, 0); H.fail_at = 1; }, NULL, 0, -1 },
	{ "btm_query_inmemsize_zero_and_max",  [](hcn_req_t *r){ bq(r, 0); put_uint(r, 3, UINT_MAX); },
	                                       [](hal_ipc_processor_desc_t *d, int) -> int { return d->in.btm_query_request_event_data.inMemSize == UINT_MAX; }, 0, 0 },
	/* ---- btm_response_event (3 args, MAC passed as a string) ---- */
	{ "btm_response_ok",                   [](hcn_req_t *r){ br(r, 0, "11:22:33:44:55:66", 1); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_br_common(d, MAC1); }, 0, 0 },
	{ "btm_response_sets_descriptor_len",  [](hcn_req_t *r){ br(r, 0, "11:22:33:44:55:66", 1); }, [](hal_ipc_processor_desc_t *d, int) -> int { return d->len == SZ; }, 0, 0 },
	{ "btm_response_mac_uppercase",        [](hcn_req_t *r){ br(r, 0, "AA:BB:CC:DD:EE:FF", 1); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_br_common(d, MAC2); }, 0, 0 },
	{ "btm_response_arg1_null",            [](hcn_req_t *r){ br(r, 1, "11:22:33:44:55:66", 1); }, NULL, 0, -1 },
	{ "btm_response_arg2_null",            [](hcn_req_t *r){ br(r, 2, "", 1); }, NULL, 0, -1 },
	{ "btm_response_arg3_null",            [](hcn_req_t *r){ br(r, 3, "11:22:33:44:55:66", 1); }, NULL, 0, -1 },
	{ "btm_response_mac_garbage_rejected", [](hcn_req_t *r){ br(r, 0, "not-a-mac", 1); }, NULL, 0, -1 },
	{ "btm_response_mac_short_rejected",   [](hcn_req_t *r){ br(r, 0, "11:22:33", 1); }, NULL, 0, -1 },
	{ "btm_response_mac_empty_rejected",   [](hcn_req_t *r){ br(r, 0, "", 1); }, NULL, 0, -1 },
	{ "btm_response_mac_17_chars_no_nul",  [](hcn_req_t *r){ br(r, 0, "11:22:33:44:55:66", 0); }, [](hal_ipc_processor_desc_t *d, int) -> int { return v_br_common(d, MAC1); }, 1, 0 },
	/* ---- other types ---- */
	{ "mgmt_frame_event_noop",             [](hcn_req_t *r){ base(r, T(mgmt_frame_event)); }, NULL, 0, 0 },
	{ "unknown_type_99",                   [](hcn_req_t *r){ base(r, 99); }, NULL, 0, -1 },
	{ "type_max_rejected",                 [](hcn_req_t *r){ base(r, hal_ipc_desc_type_max); }, NULL, 0, -1 },
	{ "non_notification_type_rejected",    [](hcn_req_t *r){ base(r, T(set_radio_stats_enable)); put_uint(r, 0, 1); }, NULL, 0, -1 },
	{ "negative_type_rejected",            [](hcn_req_t *r){ base(r, -1); }, NULL, 0, -1 },
	/* ---- crash group (forked): unchecked arg5 / NULL descriptor ---- */
	{ "crash_btm_query_arg5_null",         [](hcn_req_t *r){ bq(r, 5); }, NULL, 1, -1 },
	{ "crash_null_descriptor",             [](hcn_req_t *r){ base(r, T(steering_event)); r->d = NULL; }, NULL, 1, -1 },
	{ NULL, NULL, NULL, 0, 0 }
};
