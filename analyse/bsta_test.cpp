#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int test_handle_bsta_cap_report(void)
{
	int ret;

	printf("packet_len = %d\n", packet_len);
	printf("PCAP file 'output.pcap' created successfully\n");
	__asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);
	em_capability_t obj;
	ret = obj.handle_bsta_cap_report(packet, packet_len);
	__asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);
	return ret;
}

void run_all_tests_handle_bsta_cap_report() {
        for (int i = 0; handle_bsta_cap_report_suite[i].test_name != NULL; i++) {
                pkt_test_case_t* test = &handle_bsta_cap_report_suite[i];

                printf("--- Running Test: %s ---\n", test->test_name);

                // 1. Setup the common headers using the pcap filename from your struct
                construct_common_headers(test->pcap_file);

                // 2. Call the constructor function using your member name 'tlv_func'
                if (test->tlv_func != NULL) {
                        test->tlv_func();
                }

                // 3. Run the test and get the actual return value
                int ret = construct_pcap_and_test(test_handle_bsta_cap_report);

                // 4. Compare against your member name 'expected_result'
                if (ret == test->expected_result) {
                        printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
                } else {
                        printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                                        test->test_name, test->expected_result, ret);
                }
                printf("------------------------------------------------------------------------------------------------------------------------------\n");
        }
}

