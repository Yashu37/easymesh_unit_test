/*
 * TEST RUNNER: sg_wifi_anqpSendResponse_test
 *
 * test_sg_wifi_anqpSendResponse() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab, the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ) and the recorded-frame area past the 8400 bytes the stub may fill.  The list is built on the heap exactly like the callers do (node, element and an exactly sized data
 * block each allocated separately), so any over-read / double free / use-after-free is reported by ASan; run_all_tests also checks that every block was released (live count 0).  It compares the sent
 * frame with a reference model of the CORRECT behaviour (see the construct file).  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wsr.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static INT ret;
static mac_address_t sta_mac = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static unsigned char exp_body[9000]; static size_t exp_len;
static int exp_too_big, exp_failed;

static unsigned char pat(int i, unsigned k) { return (unsigned char)(i * 31 + k * 7 + 3); }

static wifi_anqp_node_t *build(const hwr_wsr_case_t *t)
{
	wifi_anqp_node_t *head = NULL, **tail = &head;

	for (int i = 0; i < t->n; i++) {
		const hwr_wsr_elem_t *e = &t->e[i];
		wifi_anqp_node_t *nd = (wifi_anqp_node_t *)hwr_wsr_new(sizeof(*nd));
		nd->next = NULL; nd->value = NULL;
		if (!e->null_elem) {
			wifi_anqp_elem_t *el = (wifi_anqp_elem_t *)hwr_wsr_new(sizeof(*el));
			memset(el, 0, sizeof(*el));
			el->type = e->type == 0 ? wifi_anqp_id_type_anqp : e->type == 1 ? wifi_anqp_id_type_hs : (wifi_anqp_id_type_t)2;
			if (e->type == 1) el->u.anqp_hs_id = (wifi_anqp_element_hs_subtype_t)e->id; else el->u.anqp_elem_id = (wifi_anqp_element_name_t)e->id;
			el->len = e->len;
			if (!e->data_null) {
				el->data = (UCHAR *)hwr_wsr_new(e->len ? e->len : 1);
				for (unsigned k = 0; k < e->len; k++) el->data[k] = pat(i, k);
			}
			nd->value = el;
		}
		*tail = nd; tail = &nd->next;
	}
	return head;
}

static void model(const hwr_wsr_case_t *t)
{
	unsigned total = 0; int mallocs = 0;

	exp_len = 0; exp_too_big = exp_failed = 0;
	for (int i = 0; i < t->n; i++) {
		const hwr_wsr_elem_t *e = &t->e[i];
		if (e->null_elem || e->type > 1 || e->data_null || e->len == 0) continue;
		total += (e->type == 0 ? 4 : 10) + e->len;
		if (total > 8192 - 13) { exp_too_big = 1; break; }
		if (t->malloc_fail_at && ++mallocs == t->malloc_fail_at) { exp_failed = 1; break; }
		if (e->type == 0) {
			exp_body[exp_len++] = e->id & 0xff; exp_body[exp_len++] = e->id >> 8;
			exp_body[exp_len++] = e->len & 0xff; exp_body[exp_len++] = e->len >> 8;
		} else {
			unsigned L = e->len + 6;
			exp_body[exp_len++] = 56797 & 0xff; exp_body[exp_len++] = 56797 >> 8;
			exp_body[exp_len++] = L & 0xff; exp_body[exp_len++] = L >> 8;
			exp_body[exp_len++] = 0x50; exp_body[exp_len++] = 0x6f; exp_body[exp_len++] = 0x9a;
			exp_body[exp_len++] = 0x11; exp_body[exp_len++] = (unsigned char)e->id; exp_body[exp_len++] = 0;
		}
		for (unsigned k = 0; k < e->len; k++) exp_body[exp_len++] = pat(i, k);
	}
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wsr_world.unrelated, sizeof(hwr_wsr_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_anqpSendResponse(const hwr_wsr_case_t *t, wifi_anqp_node_t *head)
{
	poison(1);
	hwr_wsr_world.in_func = 1;
	ret = hwr_sg_wifi_anqpSendResponse(t->ap, t->sta_null ? NULL : sta_mac, t->token, head);
	hwr_wsr_world.in_func = 0;
	poison(0);
}

static int check(const hwr_wsr_case_t *t)
{
	const hwr_wsr_world_t *w = &hwr_wsr_world;
	const wifi_anqpResponseFrame_t *f = (const wifi_anqpResponseFrame_t *)w->frame;
	int sent = w->mgmt_calls > 0;

	if (t->head_null) {
		if (ret != RETURN_ERR) { snprintf(why, sizeof(why), "returned %d for a NULL list, expected %d", ret, RETURN_ERR); return 0; }
		if (sent) { snprintf(why, sizeof(why), "a frame was sent for a NULL list"); return 0; }
		return 1;
	}
	if (w->live != 0) { snprintf(why, sizeof(why), "%d allocated block(s) not released", w->live); return 0; }
	if (exp_too_big) {
		if (ret != RETURN_ERR || sent) { snprintf(why, sizeof(why), "too large: returned %d, %d frame(s) sent; expected %d and none", ret, w->mgmt_calls, RETURN_ERR); return 0; }
		return 1;
	}
	if (exp_failed && !sent) { if (ret != RETURN_ERR) { snprintf(why, sizeof(why), "no frame but returned %d", ret); return 0; } return 1; }
	if (ret != RETURN_OK) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, RETURN_OK); return 0; }
	if (w->mgmt_calls != 1) { snprintf(why, sizeof(why), "%d frames sent, expected 1", w->mgmt_calls); return 0; }
	if (w->ap != (int)t->ap) { snprintf(why, sizeof(why), "frame sent on ap %d, expected %u", w->ap, t->ap); return 0; }
	if (t->sta_null ? w->sta_ptr != NULL : memcmp(w->sta_copy, sta_mac, 6) != 0) { snprintf(why, sizeof(why), "wrong station address passed"); return 0; }
	if (w->len != 13 + exp_len) { snprintf(why, sizeof(why), "frame is %zu bytes, expected %zu", w->len, 13 + exp_len); return 0; }
	if (f->public_action_hdr.cat != 4 || f->public_action_hdr.action != 0x0b) { snprintf(why, sizeof(why), "bad action header %02x %02x", f->public_action_hdr.cat, f->public_action_hdr.action); return 0; }
	if (f->gas_resp_body.token != t->token) { snprintf(why, sizeof(why), "token %02x, expected %02x", f->gas_resp_body.token, t->token); return 0; }
	if (f->gas_resp_body.comeback_delay != 0) { snprintf(why, sizeof(why), "comeback delay %u", f->gas_resp_body.comeback_delay); return 0; }
	if (f->gas_resp_body.proto_elem.id != 0x6c || f->gas_resp_body.proto_elem.len != 2) { snprintf(why, sizeof(why), "bad advertisement protocol element"); return 0; }
	if (f->gas_resp_body.proto_elem.proto_tuple.query_rsp_info != (unsigned char)t->gas_lim || f->gas_resp_body.proto_elem.proto_tuple.adv_proto_id != (unsigned char)t->gas_adv) { snprintf(why, sizeof(why), "advertisement tuple does not follow the GAS configuration"); return 0; }
	{
		unsigned want = exp_len == 0 ? wifi_gas_advertisement_protocol_not_supported : wifi_gas_status_success;
		if (f->gas_resp_body.status != want) { snprintf(why, sizeof(why), "status %u, expected %u", f->gas_resp_body.status, want); return 0; }
	}
	if (f->rsp_len != exp_len) { snprintf(why, sizeof(why), "rsp_len %u, expected %zu", f->rsp_len, exp_len); return 0; }
	if (exp_len && memcmp(f->rsp_body, exp_body, exp_len) != 0) { snprintf(why, sizeof(why), "response body differs from the expected serialisation"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wsr_case_t *t)
{
	memset(&hwr_wsr_world, 0, sizeof(hwr_wsr_world));
	hwr_wsr_world.fail_at = t->malloc_fail_at;
	memset(hwr_wsr_gas(), 0, sizeof(wifi_GASConfiguration_t));
	hwr_wsr_gas()->AdvertisementID = t->gas_adv;
	hwr_wsr_gas()->QueryResponseLengthLimit = t->gas_lim;
}

extern "C" void run_all_tests_sg_wifi_anqpSendResponse(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_anqpSendResponse_suite[i].test_name != NULL; i++) {
			hwr_wsr_case_t *test = &sg_wifi_anqpSendResponse_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			model(test);
			wifi_anqp_node_t *head = test->head_null ? NULL : build(test);

			test_sg_wifi_anqpSendResponse(test, head);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_anqpSendResponse: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
