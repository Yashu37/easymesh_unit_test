#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

int main() {
	/* unbuffered stdout so per-test lines flush before any crash/abort */
	setvbuf(stdout, NULL, _IONBF, 0);

	// dpp_dummy (rdk-wifi-hal feature_dpp/dpp.c)
	run_all_tests_dpp_dummy();

	return 0;
}
