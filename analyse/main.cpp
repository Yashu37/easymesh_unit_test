#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void run_all_tests_handle_bsta_cap_report() {
    // Ensure g_test_suite is the array containing your 72 packets
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

void run_all_tests_get_first_tlv() {
    for (int i = 0; get_first_tlv_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &get_first_tlv_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup the common headers using the pcap filename from your struct
        construct_common_headers(test->pcap_file);

        // 2. Call the constructor function using your member name 'tlv_func'
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Run the test and get the actual return value
	int ret = construct_pcap_and_test(test_get_first_tlv);
        
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

void run_all_tests_get_next_tlv() {
    for (int i = 0; get_next_tlv_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &get_next_tlv_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup the common headers using the pcap filename from your struct
        construct_common_headers(test->pcap_file);

        // 2. Call the constructor function using your member name 'tlv_func'
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Run the test and get the actual return value
	int ret = construct_pcap_and_test(test_get_next_tlv);
        
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

int main() {
run_all_tests_handle_bsta_cap_report();
    run_all_tests_get_first_tlv();
    run_all_tests_get_next_tlv();
    return 0;
}

