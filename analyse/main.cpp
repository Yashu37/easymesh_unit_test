#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/*void run_all_tests() {
    int total_passed = 0;
    int total_tests = 0;

    for (int i = 0; test_suite[i].test_name != NULL; i++) {
        int ret;
        pkt_test_case_t *test = &test_suite[i];

        printf("===================== Testing: %s ======================\n", test->test_name);

        // 1. Setup headers
        construct_common_headers(test->pcap_file);

        // 2. Construct TLVs
        if (test->func != NULL) {
            test->func();
        }

	if (test->tlv_constructor != NULL) {
            test->tlv_constructor();
        }


        // 3. Execute Test
        ret = construct_pcap_and_test();

        // 4. Pass/Fail Logic
        if (ret == test->expected_result) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
            total_passed++;
        } else {
            printf("================== %s: \033[31mFAIL\033[0m ==============\n", test->test_name);
        }
        
        printf("\n");
        total_tests++;
    }

    printf("Final Results: %d/%d Passed\n", total_passed, total_tests);
}
*/

void run_all_tests() {
    // Ensure g_test_suite is the array containing your 72 packets
    for (int i = 0; test_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &test_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup the common headers using the pcap filename from your struct
        construct_common_headers(test->pcap_file);

        // 2. Call the constructor function using your member name 'tlv_func'
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Run the test and get the actual return value
        int ret = construct_pcap_and_test();

        // 4. Compare against your member name 'expected_result'
        if (ret == test->expected_result) {
	    printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
	    printf("===== %s: \033[31mFAIL\033[0m =====\n", 
			    test->test_name,test->expected_result, ret);

        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}

int main() {
    // Run all 72 tests automatically
    run_all_tests();
    return 0;
}

/*
//A+B+C10+D+E
int pkt1_a_b_c10_d_e_rf_test(void)
{
	return run_pkt_test(__func__, "pkt49.pcap", construct_pkt49_a_b_e1_rb_tlvs, -1);
	int ret;

	printf("===================== Testing A+B+C10+D+E ======================\n");
	construct_common_headers("pkt1.pcap");
	construct_pkt1_a_b_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

	if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
	}
	else
	{
		printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
	}
	
	printf("\n");

	return 0;
}

//A+B+C10+D+E
int pkt2_a_b_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+D+E =====================\n");
	construct_common_headers("pkt2.pcap");
	construct_pkt2_a_b_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+E
int pkt4_a_b_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+E =====================\n");
	construct_common_headers("pkt4.pcap");
	construct_pkt4_a_b_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+E
int pkt3_a_b_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+E =====================\n");
	construct_common_headers("pkt3_rf.pcap");
	construct_pkt3_a_b_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+E
int pkt5_a_b_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+E =====================\n");
	construct_common_headers("pkt5.pcap");
	construct_pkt5_a_b_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D+E
int pkt6_a_b_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+D+E =====================\n");
	construct_common_headers("pkt6.pcap");
	construct_pkt6_a_b_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C10+C10+E
int pkt7_a_b_c10_c10_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+C10+E =====================\n");
	construct_common_headers("pkt7.pcap");
	construct_pkt7_a_b_c10_c10_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+C16+C16+c16+E
int pkt8_a_b_c16_c16_c16_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+C16+c16+E  =====================\n");
	construct_common_headers("pkt8.pcap");
	construct_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C16+C16+c10+C10+E
int pkt9_a_b_c10_c16_c16_c10_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C16+C16+c10+C10+E  =====================\n");
	construct_common_headers("pkt9.pcap");
	construct_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C10+D+D+D+E 
int pkt10_a_b_c10_c10_d_d_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+D+D+D+E  =====================\n");
	construct_common_headers("pkt10.pcap");
	construct_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);

        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D+D+E
int pkt11_a_b_d_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+D+D+E =====================\n");
	construct_common_headers("pkt11.pcap");
	construct_pkt11_a_b_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C16+E
int pkt12_a_b_c10_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C16+E =====================\n");
	construct_common_headers("pkt12.pcap");
	construct_pkt12_a_b_c10_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+C10+E
int pkt13_a_b_c16_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C10+E =====================\n");
	construct_common_headers("pkt13.pcap");
	construct_pkt13_a_b_c16_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C10+C16+E
int pkt14_a_b_c10_c10_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+C16+E =====================\n");
	construct_common_headers("pkt14.pcap");
	construct_pkt14_a_b_c10_c10_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+C16+C10+E
int pkt15_a_b_c16_c16_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+C10+E =====================\n");
	construct_common_headers("pkt15.pcap");
	construct_pkt15_a_b_c16_c16_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+D+D+E
int pkt16_a_b_c10_d_d_e_rf_test(void)
{
	int ret;

	printf("===================== Testing A+B+C10+D+D+E ======================\n");
	construct_common_headers("pkt16.pcap");
	construct_pkt16_a_b_c10_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+D+D+E
int pkt17_a_b_c16_d_d_e_rf_test(void)
{
	int ret;

	printf("===================== Testing A+B+C16+D+D+E ======================\n");
	construct_common_headers("pkt17.pcap");
	construct_pkt17_a_b_c16_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C10+D+E
int pkt18_a_b_c10_c10_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+D+E =====================\n");
	construct_common_headers("pkt18.pcap");
	construct_pkt18_a_b_c10_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+C16+D+E
int pkt19_a_b_c16_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+D+E =====================\n");
	construct_common_headers("pkt19.pcap");
	construct_pkt19_a_b_c16_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C16+D+E
int pkt20_a_b_c10_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C16+D+E =====================\n");
	construct_common_headers("pkt20.pcap");
	construct_pkt20_a_b_c10_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+C10+D+E
int pkt21_a_b_c16_c10_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C10+D+E =====================\n");
	construct_common_headers("pkt21.pcap");
	construct_pkt21_a_b_c16_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C10+C10+C10+D+E
int pkt22_a_b_c10_c10_c10_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+C10+D+E =====================\n");
	construct_common_headers("pkt22.pcap");
	construct_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+C16+C16+E
int pkt23_a_b_c16_c16_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+C16+E =====================\n");
	construct_common_headers("pkt22.pcap");
	construct_pkt23_a_b_c16_c16_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C16+D+C10+E
int pkt24_a_b_c16_d_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+D+C10+E =====================\n");
	construct_common_headers("pkt24.pcap");
	construct_pkt24_a_b_c16_d_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D+C10+C16+D+E
int pkt25_a_b_d_c10_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+D+C10+C16+D+E =====================\n");
	construct_common_headers("pkt25.pcap");
	construct_pkt25_a_b_d_c10_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=0)+E
int pkt1_a_b_c0_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=0)+E  ======================\n");
	construct_common_headers("pkt1.pcap");
	construct_pkt1_a_b_c0_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=1)+E
int pkt2_a_b_c1_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=1)+E  ======================\n");
	construct_common_headers("pkt2.pcap");
	construct_pkt2_a_b_c1_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=2)+E
int pkt3_a_b_c2_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=2)+E  ======================\n");
	construct_common_headers("pkt3_rb.pcap");
	construct_pkt3_a_b_c2_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=3)+E
int pkt4_a_b_c3_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=3)+E  ======================\n");
	construct_common_headers("pkt4.pcap");
	construct_pkt4_a_b_c3_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=4)+E
int pkt5_a_b_c4_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=4)+E  ======================\n");
	construct_common_headers("pkt5.pcap");
	construct_pkt5_a_b_c4_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=5)+E
int pkt6_a_b_c5_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=5)+E  ======================\n");
	construct_common_headers("pkt6.pcap");
	construct_pkt6_a_b_c5_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=6)+E
int pkt7_a_b_c6_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=6)+E  ======================\n");
	construct_common_headers("pkt7.pcap");
	construct_pkt7_a_b_c6_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=8)+E
int pkt8_a_b_c8_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=8)+E  ======================\n");
	construct_common_headers("pkt4.pcap");
	construct_pkt8_a_b_c8_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=9)+E
int pkt9_a_b_c9_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=9)+E  ======================\n");
	construct_common_headers("pkt9.pcap");
	construct_pkt9_a_b_c9_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=10)+E
int pkt10_a_b_c10_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=10)+E  ======================\n");
	construct_common_headers("pkt10.pcap");
	construct_pkt10_a_b_c10_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=11)+E
int pkt11_a_b_c11_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=11)+E  ======================\n");
	construct_common_headers("pkt11.pcap");
	construct_pkt11_a_b_c11_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=12)+E
int pkt12_a_b_c12_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=12)+E  ======================\n");
	construct_common_headers("pkt12.pcap");
	construct_pkt12_a_b_c12_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=20)+E
int pkt13_a_b_c20_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=20)+E  ======================\n");
	construct_common_headers("pkt13.pcap");
	construct_pkt13_a_b_c20_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+C(L=15)+E
int pkt14_a_b_c15_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=15)+E  ======================\n");
	construct_common_headers("pkt14.pcap");
	construct_pkt14_a_b_c15_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=0)+E
int pkt15_a_b_d0_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=0)+E  ======================\n");
	construct_common_headers("pkt15.pcap");
	construct_pkt15_a_b_d0_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=1)+E
int pkt16_a_b_d1_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=1)+E  ======================\n");
	construct_common_headers("pkt16.pcap");
	construct_pkt16_a_b_d1_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=2)+E
int pkt17_a_b_d2_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=2)+E  ======================\n");
	construct_common_headers("pkt17.pcap");
	construct_pkt17_a_b_d2_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=3)+E
int pkt18_a_b_d3_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=3)+E  ======================\n");
	construct_common_headers("pkt18.pcap");
	construct_pkt18_a_b_d3_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=4)+E
int pkt19_a_b_d4_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=4)+E  ======================\n");
	construct_common_headers("pkt19.pcap");
	construct_pkt19_a_b_d4_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=5)+E
int pkt20_a_b_d5_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=5)+E  ======================\n");
	construct_common_headers("pkt20.pcap");
	construct_pkt20_a_b_d5_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=6)+E
int pkt21_a_b_d6_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=6)+E  ======================\n");
	construct_common_headers("pkt21.pcap");
	construct_pkt21_a_b_d6_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=7)+E
int pkt22_a_b_d7_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=7)+E  ======================\n");
	construct_common_headers("pkt22.pcap");
	construct_pkt22_a_b_d7_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=8)+E
int pkt23_a_b_d8_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=8)+E  ======================\n");
	construct_common_headers("pkt23.pcap");
	construct_pkt23_a_b_d8_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=9)+E
int pkt24_a_b_d9_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=9)+E  ======================\n");
	construct_common_headers("pkt24.pcap");
	construct_pkt24_a_b_d9_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=10)+E
int pkt25_a_b_d10_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=10)+E  ======================\n");
	construct_common_headers("pkt25.pcap");
	construct_pkt25_a_b_d10_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=11)+E
int pkt26_a_b_d11_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=11)+E  ======================\n");
	construct_common_headers("pkt26.pcap");
	construct_pkt26_a_b_d11_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+D(L=14)+E
int pkt27_a_b_d14_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=14)+E  ======================\n");
	construct_common_headers("pkt27.pcap");
	construct_pkt27_a_b_d14_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
		printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

//A+B+E(3) len 0
int pkt28_a_b_e_rf_len0_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 0  ======================\n");
        construct_common_headers("pkt28.pcap");
        construct_pkt28_a_b_e_rf_len0_tlvs();
        ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(3) len 1
int pkt29_a_b_e_rb_len1_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 1  ======================\n");
        construct_common_headers("pkt29.pcap");
        construct_pkt29_a_b_e_rb_len1_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(3) len 2
int pkt30_a_b_e_rb_len2_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 2  ======================\n");
        construct_common_headers("pkt30.pcap");
        construct_pkt30_a_b_e_rb_len2_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(3) len 3
int pkt31_a_b_e_rb_len3_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 3  ======================\n");
        construct_common_headers("pkt31.pcap");
        construct_pkt31_a_b_e_rb_len3_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(3) len 4
int pkt32_a_b_e_rb_len4_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 4  ======================\n");
        construct_common_headers("pkt32.pcap");
        construct_pkt32_a_b_e_rb_len4_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(3) len 255
int pkt33_a_b_e_rb_len255_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 255  ======================\n");
        construct_common_headers("pkt33.pcap");
        construct_pkt33_a_b_e_rb_len255_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(2)
int pkt34_a_b_e_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(2)  ======================\n");
        construct_common_headers("pkt34.pcap");
        construct_pkt34_a_b_e_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(3) len 0
int pkt35_a_b_c_len0_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 0  ======================\n");
        construct_common_headers("pkt35.pcap");
        construct_pkt35_a_b_c_len0_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(3) len 1
int pkt36_a_b_c_len1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 1  ======================\n");
        construct_common_headers("pkt36.pcap");
        construct_pkt36_a_b_c_len1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(3) len 2
int pkt37_a_b_c_len2_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 2  ======================\n");
        construct_common_headers("pkt37.pcap");
        construct_pkt37_a_b_c_len2_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(3) len 3
int pkt38_a_b_c_len3_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 3  ======================\n");
        construct_common_headers("pkt38.pcap");
        construct_pkt38_a_b_c_len3_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(3) len 4
int pkt39_a_b_c_len4_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 4  ======================\n");
        construct_common_headers("pkt39.pcap");
        construct_pkt39_a_b_c_len4_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(3) len 255
int pkt40_a_b_c_len255_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 255  ======================\n");
        construct_common_headers("pkt40.pcap");
        construct_pkt40_a_b_c_len255_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+C(2)
int pkt41_a_b_c_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(2)  ======================\n");
        construct_common_headers("pkt41.pcap");
        construct_pkt41_a_b_c_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(3) len 0
int pkt42_a_b_d_len0_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 0  ======================\n");
        construct_common_headers("pkt42.pcap");
        construct_pkt42_a_b_d_len0_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(3) len 1
int pkt43_a_b_d_len1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 1  ======================\n");
        construct_common_headers("pkt43.pcap");
        construct_pkt43_a_b_d_len1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(3) len 2
int pkt44_a_b_d_len2_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 2  ======================\n");
        construct_common_headers("pkt44.pcap");
        construct_pkt44_a_b_d_len2_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(3) len 3
int pkt45_a_b_d_len3_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 3  ======================\n");
        construct_common_headers("pkt45.pcap");
        construct_pkt45_a_b_d_len3_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(3) len 4
int pkt46_a_b_d_len4_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 4  ======================\n");
        construct_common_headers("pkt46.pcap");
        construct_pkt46_a_b_d_len4_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(3) len 255
int pkt47_a_b_d_len255_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 255  ======================\n");
        construct_common_headers("pkt47.pcap");
        construct_pkt47_a_b_d_len255_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+D(2)
int pkt48_a_b_d_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(2)  ======================\n");
        construct_common_headers("pkt48.pcap");
        construct_pkt48_a_b_d_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

//A+B+E(1)
int pkt49_a_b_e1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(1)    ======================\n");
        construct_common_headers("pkt49.pcap");
        construct_pkt49_a_b_e1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

	return 0;

}

//A+B+C(1)
int pkt50_a_b_c1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(1)   ======================\n");
        construct_common_headers("pkt50.pcap");
        construct_pkt50_a_b_c1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

	return 0;

}

//A+B+D(1) 
int pkt51_a_b_d1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(1)    ======================\n");
        construct_common_headers("pkt51.pcap");
        construct_pkt51_a_b_d1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

	return 0;

}


int main(void)
{
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt1_a_b_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt2_a_b_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt4_a_b_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt3_a_b_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt5_a_b_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt6_a_b_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt7_a_b_c10_c10_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt8_a_b_c16_c16_c16_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt9_a_b_c10_c16_c16_c10_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt10_a_b_c10_c10_d_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt11_a_b_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt12_a_b_c10_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt13_a_b_c16_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt14_a_b_c10_c10_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt15_a_b_c16_c16_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt16_a_b_c10_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt17_a_b_c16_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt18_a_b_c10_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt19_a_b_c16_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt20_a_b_c10_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt21_a_b_c16_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt22_a_b_c10_c10_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt23_a_b_c16_c16_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt24_a_b_c16_d_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt25_a_b_d_c10_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");

	pkt1_a_b_c0_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt2_a_b_c1_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt3_a_b_c2_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt4_a_b_c3_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt5_a_b_c4_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt6_a_b_c5_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt7_a_b_c6_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt8_a_b_c8_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt9_a_b_c9_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt10_a_b_c10_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt11_a_b_c11_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt12_a_b_c12_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt13_a_b_c20_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt14_a_b_c15_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt15_a_b_d0_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt16_a_b_d1_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt17_a_b_d2_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt18_a_b_d3_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt19_a_b_d4_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt20_a_b_d5_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt21_a_b_d6_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt22_a_b_d7_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt23_a_b_d8_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt24_a_b_d9_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt25_a_b_d10_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt26_a_b_d11_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt27_a_b_d14_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt28_a_b_e_rf_len0_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt29_a_b_e_rb_len1_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt30_a_b_e_rb_len2_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt31_a_b_e_rb_len3_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt32_a_b_e_rb_len4_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt33_a_b_e_rb_len255_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt34_a_b_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt35_a_b_c_len0_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt36_a_b_c_len1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt37_a_b_c_len2_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt38_a_b_c_len3_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt39_a_b_c_len4_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt40_a_b_c_len255_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt41_a_b_c_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt42_a_b_d_len0_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt43_a_b_d_len1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt44_a_b_d_len2_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt45_a_b_d_len3_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt46_a_b_d_len4_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt47_a_b_d_len255_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt48_a_b_d_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt49_a_b_e1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt50_a_b_c1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt51_a_b_d1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");


	return 0;
}
*/
