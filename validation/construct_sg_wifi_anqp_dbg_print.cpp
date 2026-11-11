/*
 * UNIT TEST (input constructor): construct_sg_wifi_anqp_dbg_print
 *
 * wifi_anqp_dbg_print(level, format, ...).  Inputs crossed: the debug flag file /nvram/wifiAnqpDbg readable / not readable; /tmp/wifiAnqp openable / not openable (only matters while the function-static FILE *
 * is still NULL: rows run in an order that keeps the model of that static exact); level 0 / 1 / -5 (unused); a "%s" message of length 0 / 10 / 100 / 4000 / 4072 / 4073 / 5000 / 9000 (the text is built as
 * "<22-char time> <message>" in a 4096-byte stack buffer); a NULL format.  Expected (CORRECT behaviour): flag file not readable -> nothing happens (no open, no write); otherwise the text
 * "<time> <message>" is appended to the log file, truncated so that it never exceeds the 4095 characters (plus NUL) of the buffer, and nothing is written outside the buffer; a failing open -> no output (the
 * open is retried on the next call); a NULL format -> no output.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wdp.h"

/* name, access_ok, fopen_ok, level, msg_len, last */
hwr_wdp_case_t sg_wifi_anqp_dbg_print_suite[] = {
	{ "flag_file_missing_short",       0, 1, 1, 10, 0 },
	{ "flag_file_missing_huge_message",0, 1, 1, 5000, 0 },
	{ "log_file_open_fails",           1, 0, 1, 10, 0 },
	{ "log_file_open_fails_again",     1, 0, 1, 100, 0 },
	{ "empty_message_first_open",      1, 1, 1, 0, 0 },
	{ "short_message",                 1, 1, 1, 10, 0 },
	{ "message_100",                   1, 1, 0, 100, 0 },
	{ "message_4000",                  1, 1, 1, 4000, 0 },
	{ "message_4072_exact_fit",        1, 1, 1, 4072, 0 },
	{ "level_negative_unused",         1, 1, -5, 50, 0 },
	{ "flag_file_missing_after_open",  0, 1, 1, 50, 0 },
	{ "message_4073_one_over",         1, 1, 1, 4073, 1 },
	{ "message_5000",                  1, 1, 1, 5000, 1 },
	{ "message_9000",                  1, 1, 1, 9000, 1 },
	{ "format_null",                   1, 1, 1, -1, 1 },
	{ NULL }
};
