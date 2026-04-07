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
/*
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

pkt_test_case_t handle_bsta_cap_report_suite[] = {
    {"pkt1_a_b_c10_d_e_rf",             "pkt1.pcap",  construct_pkt1_a_b_c10_d_e_rf_tlvs,             0},
    {"pkt2_a_b_c16_d_e_rf",             "pkt2.pcap",  construct_pkt2_a_b_c16_d_e_rf_tlvs,             0},
    {"pkt4_a_b_c10_e_rf",              "pkt4.pcap",  construct_pkt4_a_b_c10_e_rf_tlvs,              0},
    {"pkt3_a_b_e_rf",                  "pkt3.pcap",  construct_pkt3_a_b_e_rf_tlvs,                  0},
    {"pkt5_a_b_c16_e_rf",              "pkt5.pcap",  construct_pkt5_a_b_c16_e_rf_tlvs,              0},
    {"pkt6_a_b_d_e_rf",                "pkt6.pcap",  construct_pkt6_a_b_d_e_rf_tlvs,                0},
    {"pkt7_a_b_c10_c10_c10_e_rf",      "pkt7.pcap",  construct_pkt7_a_b_c10_c10_c10_e_rf_tlvs,      0},
    {"pkt8_a_b_c16_c16_c16_c16_e_rf",  "pkt8.pcap",  construct_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs,  0},
    {"pkt9_a_b_c10_c16_c16_c10_c10_e_rf", "pkt9.pcap",  construct_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs, 0},
    {"pkt10_a_b_c10_c10_d_d_d_e_rf",   "pkt10.pcap", construct_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs,   0},
    {"pkt11_a_b_d_d_e_rf",             "pkt11.pcap", construct_pkt11_a_b_d_d_e_rf_tlvs,             0},
    {"pkt12_a_b_c10_c16_e_rf",         "pkt12.pcap", construct_pkt12_a_b_c10_c16_e_rf_tlvs,         0},
    {"pkt13_a_b_c16_c10_e_rf",         "pkt13.pcap", construct_pkt13_a_b_c16_c10_e_rf_tlvs,         0},
    {"pkt14_a_b_c10_c10_c16_e_rf",     "pkt14.pcap", construct_pkt14_a_b_c10_c10_c16_e_rf_tlvs,     0},
    {"pkt15_a_b_c16_c16_c10_e_rf",     "pkt15.pcap", construct_pkt15_a_b_c16_c16_c10_e_rf_tlvs,     0},
    {"pkt16_a_b_c10_d_d_e_rf",         "pkt16.pcap", construct_pkt16_a_b_c10_d_d_e_rf_tlvs,         0},
    {"pkt17_a_b_c16_d_d_e_rf",         "pkt17.pcap", construct_pkt17_a_b_c16_d_d_e_rf_tlvs,         0},
    {"pkt18_a_b_c10_c10_d_e_rf",       "pkt18.pcap", construct_pkt18_a_b_c10_c10_d_e_rf_tlvs,       0},
    {"pkt19_a_b_c16_c16_d_e_rf",       "pkt19.pcap", construct_pkt19_a_b_c16_c16_d_e_rf_tlvs,       0},
    {"pkt20_a_b_c10_c16_d_e_rf",       "pkt20.pcap", construct_pkt20_a_b_c10_c16_d_e_rf_tlvs,       0},
    {"pkt21_a_b_c16_c10_d_e_rf",       "pkt21.pcap", construct_pkt21_a_b_c16_c10_d_e_rf_tlvs,       0},
    {"pkt22_a_b_c10_c10_c10_d_e_rf",   "pkt22.pcap", construct_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs,   0},
    {"pkt23_a_b_c16_c16_c16_e_rf",     "pkt23.pcap", construct_pkt23_a_b_c16_c16_c16_e_rf_tlvs,     0},
    {"pkt24_a_b_c16_d_c10_e_rf",       "pkt24.pcap", construct_pkt24_a_b_c16_d_c10_e_rf_tlvs,       0},
    {"pkt25_a_b_d_c10_c16_d_e_rf",     "pkt25.pcap", construct_pkt25_a_b_d_c10_c16_d_e_rf_tlvs,     0},
    // { Name, PCAP, TLV_Constructor, Pass_Condition }
    {"pkt1_a_b_c0_e_rb",       "pkt1rb.pcap",  construct_pkt1_a_b_c0_e_rb_tlvs,       -1},
    {"pkt2_a_b_c1_e_rb",       "pkt2rb.pcap",  construct_pkt2_a_b_c1_e_rb_tlvs,       -1},
    {"pkt3_a_b_c2_e_rb",       "pkt3rb.pcap",  construct_pkt3_a_b_c2_e_rb_tlvs,       -1},
    {"pkt4_a_b_c3_e_rb",       "pkt4rb.pcap",  construct_pkt4_a_b_c3_e_rb_tlvs,       -1},
    {"pkt5_a_b_c4_e_rb",       "pkt5rb.pcap",  construct_pkt5_a_b_c4_e_rb_tlvs,       -1},
    {"pkt6_a_b_c5_e_rb",       "pkt6rb.pcap",  construct_pkt6_a_b_c5_e_rb_tlvs,       -1},
    {"pkt7_a_b_c6_e_rb",       "pkt7rb.pcap",  construct_pkt7_a_b_c6_e_rb_tlvs,       -1},
    {"pkt8_a_b_c8_e_rb",       "pkt8rb.pcap",  construct_pkt8_a_b_c8_e_rb_tlvs,       -1},
    {"pkt9_a_b_c9_e_rb",       "pkt9rb.pcap",  construct_pkt9_a_b_c9_e_rb_tlvs,       -1},
    {"pkt10_a_b_c10_e_rb",     "pkt10rb.pcap", construct_pkt10_a_b_c10_e_rb_tlvs,     -1},
    {"pkt11_a_b_c11_e_rb",     "pkt11rb.pcap", construct_pkt11_a_b_c11_e_rb_tlvs,     -1},
    {"pkt12_a_b_c12_e_rb",     "pkt12rb.pcap", construct_pkt12_a_b_c12_e_rb_tlvs,     -1},
    {"pkt13_a_b_c20_e_rb",     "pkt13rb.pcap", construct_pkt13_a_b_c20_e_rb_tlvs,     -1},
    {"pkt14_a_b_c15_e_rb",     "pkt14rb.pcap", construct_pkt14_a_b_c15_e_rb_tlvs,     -1},
    {"pkt15_a_b_d0_e_rb",      "pkt15rb.pcap", construct_pkt15_a_b_d0_e_rb_tlvs,      -1},
    {"pkt16_a_b_d1_e_rb",      "pkt16rb.pcap", construct_pkt16_a_b_d1_e_rb_tlvs,      -1},
    {"pkt17_a_b_d2_e_rb",      "pkt17rb.pcap", construct_pkt17_a_b_d2_e_rb_tlvs,      -1},
    {"pkt18_a_b_d3_e_rb",      "pkt18rb.pcap", construct_pkt18_a_b_d3_e_rb_tlvs,      -1},
    {"pkt19_a_b_d4_e_rb",      "pkt19rb.pcap", construct_pkt19_a_b_d4_e_rb_tlvs,      -1},
    {"pkt20_a_b_d5_e_rb",      "pkt20rb.pcap", construct_pkt20_a_b_d5_e_rb_tlvs,      -1},
    {"pkt21_a_b_d6_e_rb",      "pkt21rb.pcap", construct_pkt21_a_b_d6_e_rb_tlvs,      -1},
    {"pkt22_a_b_d7_e_rb",      "pkt22rb.pcap", construct_pkt22_a_b_d7_e_rb_tlvs,      -1},
    {"pkt23_a_b_d8_e_rb",      "pkt23rb.pcap", construct_pkt23_a_b_d8_e_rb_tlvs,      -1},
    {"pkt24_a_b_d9_e_rb",      "pkt24rb.pcap", construct_pkt24_a_b_d9_e_rb_tlvs,      -1},
    {"pkt25_a_b_d10_e_rb",     "pkt25rb.pcap", construct_pkt25_a_b_d10_e_rb_tlvs,     -1},
    {"pkt26_a_b_d11_e_rb",     "pkt26rb.pcap", construct_pkt26_a_b_d11_e_rb_tlvs,     -1},
    {"pkt27_a_b_d14_e_rb",     "pkt27rb.pcap", construct_pkt27_a_b_d14_e_rb_tlvs,     -1},
    {"pkt28_a_b_e_rf_len0",    "pkt28rf.pcap", construct_pkt28_a_b_e_rf_len0_tlvs,    0},
    {"pkt29_a_b_e_rb_len1",    "pkt29rb.pcap", construct_pkt29_a_b_e_rb_len1_tlvs,    -1},
    {"pkt30_a_b_e_rb_len2",    "pkt30rb.pcap", construct_pkt30_a_b_e_rb_len2_tlvs,    -1},
    {"pkt31_a_b_e_rb_len3",    "pkt31rb.pcap", construct_pkt31_a_b_e_rb_len3_tlvs,    -1},
    {"pkt32_a_b_e_rb_len4",    "pkt32rb.pcap", construct_pkt32_a_b_e_rb_len4_tlvs,    -1},
    {"pkt33_a_b_e_rb_len255",  "pkt33rb.pcap", construct_pkt33_a_b_e_rb_len255_tlvs,  -1},
    {"pkt34_a_b_e_rb",         "pkt34rb.pcap", construct_pkt34_a_b_e_rb_tlvs,         -1},
    {"pkt35_a_b_c_len0_rb",    "pkt35rb.pcap", construct_pkt35_a_b_c_len0_rb_tlvs,    -1},
    {"pkt36_a_b_c_len1_rb",    "pkt36rb.pcap", construct_pkt36_a_b_c_len1_rb_tlvs,    -1},
    {"pkt37_a_b_c_len2_rb",    "pkt37rb.pcap", construct_pkt37_a_b_c_len2_rb_tlvs,    -1},
    {"pkt38_a_b_c_len3_rb",    "pkt38rb.pcap", construct_pkt38_a_b_c_len3_rb_tlvs,    -1},
    {"pkt39_a_b_c_len4_rb",    "pkt39rb.pcap", construct_pkt39_a_b_c_len4_rb_tlvs,    -1},
    {"pkt40_a_b_c_len255_rb",  "pkt40rb.pcap", construct_pkt40_a_b_c_len255_rb_tlvs,  -1},
    {"pkt41_a_b_c_rb",         "pkt41rb.pcap", construct_pkt41_a_b_c_rb_tlvs,         -1},
    {"pkt42_a_b_d_len0_rb",    "pkt42rb.pcap", construct_pkt42_a_b_d_len0_rb_tlvs,    -1},
    {"pkt43_a_b_d_len1_rb",    "pkt43rb.pcap", construct_pkt43_a_b_d_len1_rb_tlvs,    -1},
    {"pkt44_a_b_d_len2_rb",    "pkt44rb.pcap", construct_pkt44_a_b_d_len2_rb_tlvs,    -1},
    {"pkt45_a_b_d_len3_rb",    "pkt45rb.pcap", construct_pkt45_a_b_d_len3_rb_tlvs,    -1},
    {"pkt46_a_b_d_len4_rb",    "pkt46rb.pcap", construct_pkt46_a_b_d_len4_rb_tlvs,    -1},
    {"pkt47_a_b_d_len255_rb",  "pkt47rb.pcap", construct_pkt47_a_b_d_len255_rb_tlvs,  -1},
    {"pkt48_a_b_d_rb",         "pkt48rb.pcap", construct_pkt48_a_b_d_rb_tlvs,         -1},
    {"pkt49_a_b_e1_rb",        "pkt49rb.pcap", construct_pkt49_a_b_e1_rb_tlvs,        -1},
    {"pkt50_a_b_c1_rb",        "pkt50rb.pcap", construct_pkt50_a_b_c1_rb_tlvs,        -1},
    {"pkt51_a_b_d1_rb",        "pkt51rb.pcap", construct_pkt51_a_b_d1_rb_tlvs,        -1},

    {NULL, NULL, NULL, 0} // Null terminator to mark the end of the array
};
*/
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

