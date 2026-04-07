#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/*
uint8_t packet[4096] = {0};
uint8_t *ptr;
uint32_t packet_len = 0;
FILE *fp;

void construct_global_header(void)
{
        // =========================
        // 1. Global Header
        // =========================
        struct pcap_global_header gh;

        gh.magic_number  = 0xa1b2c3d4;
        gh.version_major = 2;
        gh.version_minor = 4;
        gh.thiszone      = 0;
        gh.sigfigs       = 0;
        gh.snaplen       = 65535;
        gh.network       = 1; // Ethernet

        fwrite(&gh, sizeof(gh), 1, fp);
}

void construct_ethernet_header(void)
{
        // ---- Ethernet ----
        uint8_t dst[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t src[6] = {0x11,0x22,0x33,0x44,0x55,0x66};

        memcpy(ptr, dst, 6); ptr += 6;
        memcpy(ptr, src, 6); ptr += 6;

        *(uint16_t*)ptr = htons(0x893A); ptr += 2;
}

void construct_1905_header(void)
{
        // ---- 1905 Header ----
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0x8028); ptr += 2;
        *(uint16_t*)ptr = htons(0x0001); ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x80;
}

void construct_pcap_header(void)
{
        // =========================
        // 3. Packet Header
        // =========================
        struct pcap_packet_header ph;

        struct timeval tv;
        gettimeofday(&tv, NULL);

        ph.ts_sec  = tv.tv_sec;
        ph.ts_usec = tv.tv_usec;
        ph.incl_len = packet_len;
        ph.orig_len = packet_len;

        fwrite(&ph, sizeof(ph), 1, fp);

        // =========================
        // 4. Write Packet Data
        // =========================
        fwrite(packet, packet_len, 1, fp);
}
*/

int test_get_next_tlv(void)//change the name
{
        //int ret;
	em_tlv_t* ret = NULL;

        printf("packet_len = %d\n", packet_len);
        printf("PCAP file 'output.pcap' created successfully\n");
        __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);
        em_msg_t obj;
       // ret = obj.get_first_tlv(packet, packet_len);
        em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(packet);
	ret = obj.get_next_tlv(current_tlv,reinterpret_cast<em_tlv_t*>(packet), packet_len);
        __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);
       // return ret;
       // If ret is NOT NULL, the test passed (return 0 or 1 based on your framework)
       // If ret IS NULL, the test failed (return -1)
	return (ret != NULL) ? 0 : -1;
}
/*
void construct_common_headers(const char *pcap_file_name)
{
        fp = fopen(pcap_file_name, "wb");
        construct_global_header();
        ptr = packet;
        construct_ethernet_header();
        construct_1905_header();
}

int construct_pcap_and_test(void)
{
        int ret;

        packet_len = ptr - packet;
        construct_pcap_header();
        fclose(fp);
        ret = test_get_next_tlv();
        return ret;
}
*/
void construct_pkt0_a_b_e_rb_len0_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt1_a_b_e_rb_len1_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(1); ptr += 2;

}

void construct_pkt2_a_b_e_rb_len2_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(2); ptr += 2;

}

void construct_pkt3_a_b_e_rb_len3_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(3); ptr += 2;

}

void construct_pkt4_a_b_e_rb_len4_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(4); ptr += 2;

}

void construct_pkt5_a_b_e_rb_len255_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(255); ptr += 2;

}

void construct_pkt6_a_b_e_rb_tlvs(void)
{
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt7_a_b_c_len0_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_pkt8_a_b_c_len1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_pkt9_a_b_c_len2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_pkt10_a_b_c_len3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_pkt11_a_b_c_len4_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;


}

void construct_pkt12_a_b_c_len255_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_pkt13_a_b_c_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_pkt14_a_b_d_len0_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_pkt15_a_b_d_len1_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_pkt16_a_b_d_len2_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_pkt17_a_b_d_len3_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_pkt18_a_b_d_len4_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;


}

void construct_pkt19_a_b_d_len255_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_pkt20_a_b_d_rb_tlvs(void)
{
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_pkt21_a_b_e1_rb_tlvs(void)
{
        *ptr++ = 0x00;
}

void construct_pkt22_a_b_c1_rb_tlvs(void)
{
        *ptr++ = 0xCB;
}

void construct_pkt23_a_b_d1_rb_tlvs(void)
{
        *ptr++ = 0x90;
}

void construct_pkt24_a_b_c_len0_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt25_a_b_c_len1_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt26_a_b_c_len2_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt27_a_b_c_len3_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt28_a_b_c_len4_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_pkt29_a_b_c_len5_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(5);
        ptr += 2;

        for(int i = 0; i < 5; i++){
                *ptr++ = i;
        }

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt30_a_b_c_len6_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(6);
        ptr += 2;

        for(int i = 0; i < 6; i++){
                *ptr++ = i;
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt31_a_b_c_len7_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(7);
        ptr += 2;

        for(int i = 0; i < 7; i++){
                *ptr++ = i;
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt32_a_b_c_len8_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(8);
        ptr += 2;

        for(int i = 0; i < 8; i++){
                *ptr++ = i;
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt33_a_b_c_len0_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_pkt34_a_b_c_len1_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;
        *ptr++ = 0xAA;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt35_a_b_c_len2_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt36_a_b_c_len3_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt37_a_b_c_len4_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;

        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_pkt38_a_b_c_len5_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(5);
        ptr += 2;

        for(int i = 0; i < 5; i++){
                *ptr++ = i;
        }

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt39_a_b_c_len6_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(6);
        ptr += 2;

        for(int i = 0; i < 6; i++){
                *ptr++ = i;
        }

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt40_a_b_c_len7_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(7);
        ptr += 2;

        for(int i = 0; i < 7; i++){
                *ptr++ = i;
        }

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt41_a_b_c_len8_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(8);
        ptr += 2;

        for(int i = 0; i < 8; i++){
                *ptr++ = i;
        }

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_pkt42_a_b_c_len0_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

	*ptr++ = 0x00;

}

void construct_pkt43_a_b_c_len1_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;
        *ptr++ = 0xAA;

	*ptr++ = 0x00;

}

void construct_pkt44_a_b_c_len2_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

	*ptr++ = 0x00;

}

void construct_pkt45_a_b_c_len3_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;

	*ptr++ = 0x00;

}

void construct_pkt46_a_b_c_len4_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;

	*ptr++ = 0x00;
}

void construct_pkt47_a_b_c_len5_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(5);
        ptr += 2;

        for(int i = 0; i < 5; i++){
                *ptr++ = i;
        }

	*ptr++ = 0x00;

}

void construct_pkt48_a_b_c_len6_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(6);
        ptr += 2;

        for(int i = 0; i < 6; i++){
                *ptr++ = i;
        }

	*ptr++ = 0x00;

}

void construct_pkt49_a_b_c_len7_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(7);
        ptr += 2;

        for(int i = 0; i < 7; i++){
                *ptr++ = i;
        }

	*ptr++ = 0x00;

}

void construct_pkt50_a_b_c_len8_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(8);
        ptr += 2;

        for(int i = 0; i < 8; i++){
                *ptr++ = i;
        }

	*ptr++ = 0x00;

}

pkt_test_case_t get_next_tlv_suite[] = {
	{"pkt0_a_b_e_rb_len0",      "pkt0rb.pcap",  construct_pkt0_a_b_e_rb_len0_tlvs,    -1},
    {"pkt1_a_b_e_rb_len1",      "pkt1rb.pcap",  construct_pkt1_a_b_e_rb_len1_tlvs,    -1},
    {"pkt2_a_b_e_rb_len2",      "pkt2rb.pcap",  construct_pkt2_a_b_e_rb_len2_tlvs,    -1},
    {"pkt3_a_b_e_rb_len3",      "pkt3rb.pcap",  construct_pkt3_a_b_e_rb_len3_tlvs,    -1},
    {"pkt4_a_b_e_rb_len4",      "pkt4rb.pcap",  construct_pkt4_a_b_e_rb_len4_tlvs,    -1},
    {"pkt5_a_b_e_rb_len255",    "pkt5rb.pcap",  construct_pkt5_a_b_e_rb_len255_tlvs,  -1},
    {"pkt6_a_b_e_rb",           "pkt6rb.pcap",  construct_pkt6_a_b_e_rb_tlvs,          -1},
    {"pkt7_a_b_c_len0_rb",      "pkt7rb.pcap",  construct_pkt7_a_b_c_len0_rb_tlvs,    -1},
    {"pkt8_a_b_c_len1_rb",      "pkt8rb.pcap",  construct_pkt8_a_b_c_len1_rb_tlvs,    -1},
    {"pkt9_a_b_c_len2_rb",      "pkt9rb.pcap",  construct_pkt9_a_b_c_len2_rb_tlvs,    -1},
    {"pkt10_a_b_c_len3_rb",     "pkt10rb.pcap", construct_pkt10_a_b_c_len3_rb_tlvs,   -1},
    {"pkt11_a_b_c_len4_rb",     "pkt11rb.pcap", construct_pkt11_a_b_c_len4_rb_tlvs,   -1},
    {"pkt12_a_b_c_len255_rb",   "pkt12rb.pcap", construct_pkt12_a_b_c_len255_rb_tlvs, -1},
    {"pkt13_a_b_c_rb",          "pkt13rb.pcap", construct_pkt13_a_b_c_rb_tlvs,        -1},
    {"pkt14_a_b_d_len0_rb",     "pkt14rb.pcap", construct_pkt14_a_b_d_len0_rb_tlvs,   -1},
    {"pkt15_a_b_d_len1_rb",     "pkt15rb.pcap", construct_pkt15_a_b_d_len1_rb_tlvs,   -1},
    {"pkt16_a_b_d_len2_rb",     "pkt16rb.pcap", construct_pkt16_a_b_d_len2_rb_tlvs,   -1},
    {"pkt17_a_b_d_len3_rb",     "pkt17rb.pcap", construct_pkt17_a_b_d_len3_rb_tlvs,   -1},
    {"pkt18_a_b_d_len4_rb",     "pkt18rb.pcap", construct_pkt18_a_b_d_len4_rb_tlvs,   -1},
    {"pkt19_a_b_d_len255_rb",   "pkt19rb.pcap", construct_pkt19_a_b_d_len255_rb_tlvs, -1},
    {"pkt20_a_b_d_rb",          "pkt20rb.pcap", construct_pkt20_a_b_d_rb_tlvs,        -1},
    {"pkt21_a_b_e1_rb",         "pkt21rb.pcap", construct_pkt21_a_b_e1_rb_tlvs,       -1},
    {"pkt22_a_b_c1_rb",         "pkt22rb.pcap", construct_pkt22_a_b_c1_rb_tlvs,       -1},
    {"pkt23_a_b_d1_rb",         "pkt23rb.pcap", construct_pkt23_a_b_d1_rb_tlvs,       -1},
    {"pkt24_a_b_c_len0_e3_rb",  "pkt24rb.pcap", construct_pkt24_a_b_c_len0_e3_rb_tlvs, -1},
    {"pkt25_a_b_c_len1_e3_rb",  "pkt25rb.pcap", construct_pkt25_a_b_c_len1_e3_rb_tlvs, -1},
    {"pkt26_a_b_c_len2_e_rb",   "pkt26rb.pcap", construct_pkt26_a_b_c_len2_e_rb_tlvs,  -1},
    {"pkt27_a_b_c_len3_e3_rb",  "pkt27rb.pcap", construct_pkt27_a_b_c_len3_e3_rb_tlvs, -1},
    {"pkt28_a_b_c_len4_e3_rb",  "pkt28rb.pcap", construct_pkt28_a_b_c_len4_e3_rb_tlvs, -1},
    {"pkt29_a_b_c_len5_e3_rb",  "pkt29rb.pcap", construct_pkt29_a_b_c_len5_e3_rb_tlvs, -1},
    {"pkt30_a_b_c_len6_e3_rb",  "pkt30rb.pcap", construct_pkt30_a_b_c_len6_e3_rb_tlvs, -1},
    {"pkt31_a_b_c_len7_e3_rb",  "pkt31rb.pcap", construct_pkt31_a_b_c_len7_e3_rb_tlvs, -1},
    {"pkt32_a_b_c_len8_e3_rb",  "pkt32rb.pcap", construct_pkt32_a_b_c_len8_e3_rb_tlvs, -1},
    {"pkt33_a_b_c_len0_e2_rb",  "pkt33rb.pcap", construct_pkt33_a_b_c_len0_e2_rb_tlvs, -1},
    {"pkt34_a_b_c_len1_e2_rb",  "pkt34rb.pcap", construct_pkt34_a_b_c_len1_e2_rb_tlvs, -1},
    {"pkt35_a_b_c_len2_e2_rb",  "pkt35rb.pcap", construct_pkt35_a_b_c_len2_e2_rb_tlvs, -1},
    {"pkt36_a_b_c_len3_e2_rb",  "pkt36rb.pcap", construct_pkt36_a_b_c_len3_e2_rb_tlvs, -1},
    {"pkt37_a_b_c_len4_e2_rb",  "pkt37rb.pcap", construct_pkt37_a_b_c_len4_e2_rb_tlvs, -1},
    {"pkt38_a_b_c_len5_e2_rb",  "pkt38rb.pcap", construct_pkt38_a_b_c_len5_e2_rb_tlvs, -1},
    {"pkt39_a_b_c_len6_e2_rb",  "pkt39rb.pcap", construct_pkt39_a_b_c_len6_e2_rb_tlvs, -1},
    {"pkt40_a_b_c_len7_e2_rb",  "pkt40rb.pcap", construct_pkt40_a_b_c_len7_e2_rb_tlvs, -1},
    {"pkt41_a_b_c_len8_e2_rb",  "pkt41rb.pcap", construct_pkt41_a_b_c_len8_e2_rb_tlvs, -1},
    {"pkt42_a_b_c_len0_e1_rb",  "pkt42rb.pcap", construct_pkt42_a_b_c_len0_e1_rb_tlvs, -1},
    {"pkt43_a_b_c_len1_e1_rb",  "pkt43rb.pcap", construct_pkt43_a_b_c_len1_e1_rb_tlvs, -1},
    {"pkt44_a_b_c_len2_e1_rb",  "pkt44rb.pcap", construct_pkt44_a_b_c_len2_e1_rb_tlvs, -1},
    {"pkt45_a_b_c_len3_e1_rb",  "pkt45rb.pcap", construct_pkt45_a_b_c_len3_e1_rb_tlvs, -1},
    {"pkt46_a_b_c_len4_e1_rb",  "pkt46rb.pcap", construct_pkt46_a_b_c_len4_e1_rb_tlvs, -1},
    {"pkt47_a_b_c_len5_e1_rb",  "pkt47rb.pcap", construct_pkt47_a_b_c_len5_e1_rb_tlvs, -1},
    {"pkt48_a_b_c_len6_e1_rb",  "pkt48rb.pcap", construct_pkt48_a_b_c_len6_e1_rb_tlvs, -1},
    {"pkt49_a_b_c_len7_e1_rb",  "pkt49rb.pcap", construct_pkt49_a_b_c_len7_e1_rb_tlvs, -1},
    {"pkt50_a_b_c_len8_e1_rb",  "pkt50rb.pcap", construct_pkt50_a_b_c_len8_e1_rb_tlvs, -1},

    {NULL, NULL, NULL, 0} 
};
