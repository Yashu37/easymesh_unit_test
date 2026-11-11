/*
 * UNIT TEST (input constructor): construct_sg_wifi_dpp_dbg_print
 *
 * wifi_dpp_dbg_print(format, ...).  Inputs crossed: the debug flag file /nvram/wifiDppDbg readable / not readable; /tmp/wifiDPP openable / not openable (only matters while the function-static FILE *
 * is still NULL: rows run in an order that keeps the model of that static exact); a "%s" message of length 0 / 10 / 100 / 2000 / 2024 / 2025 / 3000 / 9000 (the text is built as
 * "<22-char time> <message>" in a 2048-byte stack buffer); a NULL format.  Expected (CORRECT behaviour): flag file not readable -> nothing happens (no open, no write); otherwise the text
 * "<time> <message>" is appended to the log file, truncated so that it never exceeds the 2047 characters (plus NUL) of the buffer, and nothing is written outside the buffer; a failing open -> no output (the
 * open is retried on the next call); a NULL format -> no output.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wdb.h"

/* name, access_ok, fopen_ok, msg_len, last */
hwr_wdb_case_t sg_wifi_dpp_dbg_print_suite[] = {
	{ "flag_file_missing_short",       0, 1, 10, 0 },
	{ "flag_file_missing_huge_message",0, 1, 3000, 0 },
	{ "log_file_open_fails",           1, 0, 10, 0 },
	{ "log_file_open_fails_again",     1, 0, 100, 0 },
	{ "empty_message_first_open",      1, 1, 0, 0 },
	{ "short_message",                 1, 1, 10, 0 },
	{ "message_100",                   1, 1, 100, 0 },
	{ "message_2000",                  1, 1, 2000, 0 },
	{ "message_2024_exact_fit",        1, 1, 2024, 0 },
	{ "message_1500",                  1, 1, 1500, 0 },
	{ "flag_file_missing_after_open",  0, 1, 50, 0 },
	{ "message_2025_one_over",         1, 1, 2025, 1 },
	{ "message_3000",                  1, 1, 3000, 1 },
	{ "message_9000",                  1, 1, 9000, 1 },
	{ "format_null",                   1, 1, -1, 1 },
	{ NULL }
};
