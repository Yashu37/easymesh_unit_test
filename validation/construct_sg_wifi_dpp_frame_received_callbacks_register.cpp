/*
 * UNIT TEST (input constructor): construct_sg_wifi_dpp_frame_received_callbacks_register
 *
 * wifi_dpp_frame_received_callbacks_register(auth, config_req, config_result, reconfig_announce, reconfig_auth_rsp).  Inputs crossed: each of the five callbacks NULL / callback A / callback B (all
 * equal, all different, only one slot set for each of the five positions, mixed with NULLs); the callbacks held before none / A / B per slot; one and two consecutive registrations (the second passes the
 * swapped callbacks).  Expected (CORRECT behaviour): every slot holds exactly the callback passed for it in the last call (NULL clears a slot, a later one replaces an earlier one), the neighbouring table
 * members are untouched, the function returns RETURN_OK and the accessor is used once per call.  A NULL callbacks table cannot occur: the real accessor returns the address of a global (design note, not
 * modelled).  No crash case is expected.
 */
#include "hwr_wdg.h"

/* name, old[5], arg[5], calls, last */
hwr_wdg_case_t sg_wifi_dpp_frame_received_callbacks_register_suite[] = {
	{ "all_callbacks_a",                { 0,0,0,0,0 }, { 1,1,1,1,1 }, 1, 0 },
	{ "all_callbacks_b",                { 0,0,0,0,0 }, { 2,2,2,2,2 }, 1, 0 },
	{ "all_null_when_empty",            { 0,0,0,0,0 }, { 0,0,0,0,0 }, 1, 0 },
	{ "mixed_a_b_a_b_a",                { 0,0,0,0,0 }, { 1,2,1,2,1 }, 1, 0 },
	{ "only_auth_set",                  { 0,0,0,0,0 }, { 1,0,0,0,0 }, 1, 0 },
	{ "only_config_req_set",            { 0,0,0,0,0 }, { 0,1,0,0,0 }, 1, 0 },
	{ "only_config_result_set",         { 0,0,0,0,0 }, { 0,0,1,0,0 }, 1, 0 },
	{ "only_reconfig_announce_set",     { 0,0,0,0,0 }, { 0,0,0,1,0 }, 1, 0 },
	{ "only_reconfig_auth_rsp_set",     { 0,0,0,0,0 }, { 0,0,0,0,1 }, 1, 0 },
	{ "replace_all_a_with_b",           { 1,1,1,1,1 }, { 2,2,2,2,2 }, 1, 0 },
	{ "null_clears_all",                { 1,2,1,2,1 }, { 0,0,0,0,0 }, 1, 0 },
	{ "null_clears_only_one_slot",      { 1,1,1,1,1 }, { 1,1,0,1,1 }, 1, 0 },
	{ "same_callbacks_again",           { 1,2,1,2,1 }, { 1,2,1,2,1 }, 1, 0 },
	{ "two_registrations_swapped",      { 0,0,0,0,0 }, { 1,2,1,2,1 }, 2, 0 },
	{ "two_registrations_null_then_set",{ 1,1,1,1,1 }, { 0,0,0,0,0 }, 2, 0 },
	{ "two_registrations_all_a",        { 0,0,0,0,0 }, { 1,1,1,1,1 }, 2, 0 },
	{ NULL }
};
