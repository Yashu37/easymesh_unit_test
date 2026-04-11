#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

//test_handle_bsta_cap_report
void construct_handle_bsta_cap_report_pkt1_a_b_c10_d_e_rf_tlvs(void)
{
        // ---- TLV 0xCB ----
        *ptr++ = 0xCB;
        *(uint16_t*)ptr = htons(7); ptr += 2;

        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6); ptr += 6;
        *ptr++ = 0x00;

        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt2_a_b_c16_d_e_rf_tlvs(void)
{
        *ptr++ = 0xCB;

        // length = 13 (value only)
        uint16_t len = htons(13);
        memcpy(ptr, &len, 2);
        ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        // Flags (bit7 = 1 → MAC included)
        *ptr++ = 0x80;

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt3_a_b_e_rf_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt4_a_b_c10_e_rf_tlvs(void)
{
        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt5_a_b_c16_e_rf_tlvs(void)
{
        *ptr++ = 0xCB;

        // length = 13 (value only)
        uint16_t len = htons(13);
        memcpy(ptr, &len, 2);
        ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        // Flags (bit7 = 1 → MAC included)
        *ptr++ = 0x80;

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;


        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt6_a_b_d_e_rf_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e_rf_tlvs(void)
{
        // 3 × C10 TLVs 0xCB
        // =========================
        for (int i = 0; i < 3; i++) {

                *ptr++ = 0xCB; // Type

                uint16_t len = htons(7); // VALUE = 7
                memcpy(ptr, &len, 2);
                ptr += 2;

                // 7 bytes dummy data
                uint8_t val[7];
                for (int j = 0; j < 7; j++) {
                        val[j] = (uint8_t)(j + 1 + i);
                }

                memcpy(ptr, val, 7);
                ptr += 7;
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs(void)
{
        // 4 × C16 TLVs
        // =========================
        for (int i = 0; i < 4; i++) {

                *ptr++ = 0xCB; // TLV Type

                uint16_t len = htons(13); // VALUE = 13
                memcpy(ptr, &len, 2);
                ptr += 2;

                // 13-byte value (valid structure)
                uint8_t val[13];

                // First 6 bytes (radio MAC)
                for (int j = 0; j < 6; j++) {
                        val[j] = (uint8_t)(0x10 + j + i);
                }

                // Flag
                val[6] = 0x80;

                // Next 6 bytes (STA MAC)
                for (int j = 0; j < 6; j++) {
                        val[7 + j] = (uint8_t)(0xA0 + j + i);
                }

                memcpy(ptr, val, 13);
                ptr += 13;
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs(void)
{
        // C10
        // =========================
        *ptr++ = 0xCB;
        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        // =========================
        // C16
        // =========================
        for (int k = 0; k < 2; k++) {
                *ptr++ = 0xCB;

                uint16_t len16 = htons(13);
                memcpy(ptr, &len16, 2); ptr += 2;

                // 6 bytes radio MAC
                for (int j = 0; j < 6; j++)
                        *ptr++ = (uint8_t)(0x10 + j + k);

                *ptr++ = 0x80; // flag

                // 6 bytes STA MAC
                for (int j = 0; j < 6; j++)
                        *ptr++ = (uint8_t)(0xA0 + j + k);
        }

        // =========================
        // C10
        // =========================
        for (int t = 0; t < 2; t++) {
                *ptr++ = 0xCB;

                uint16_t len = htons(7);
                memcpy(ptr, &len, 2); ptr += 2;

                for (int j = 0; j < 7; j++)
                        *ptr++ = (uint8_t)(j + 5 + t);
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs(void)
{
        // C10 + C10
        // =========================
        for (int i = 0; i < 2; i++) {
                *ptr++ = 0xCB;

                uint16_t len = htons(7);
                memcpy(ptr, &len, 2); ptr += 2;

                for (int j = 0; j < 7; j++)
                        *ptr++ = (uint8_t)(j + 1 + i);
        }

        // =========================
        // D + D + D  (0x90)
        // =========================
        for (int i = 0; i < 3; i++) {

                *ptr++ = 0x90;   // D type

                uint16_t len = htons(12);
                memcpy(ptr, &len, 2); ptr += 2;

                // 12-byte value (2 MACs example)
                for (int j = 0; j < 12; j++)
                        *ptr++ = (uint8_t)(0x20 + j + i);
        }


        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt11_a_b_d_d_e_rf_tlvs(void)
{
        // D + D  (0x90)
        // =========================

        for (int i = 0; i < 2; i++) {

                *ptr++ = 0x90;  // TLV type

                uint16_t len = htons(12);
                memcpy(ptr, &len, 2); ptr += 2;

                // 12-byte value
                for (int j = 0; j < 12; j++)
                        *ptr++ = (uint8_t)(0x30 + j + i);
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt12_a_b_c10_c16_e_rf_tlvs(void)
{
        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        // =========================
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80; // flag

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt13_a_b_c16_c10_e_rf_tlvs(void)
{
        // =========================
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80; // flag

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e_rf_tlvs(void)
{
        // C10 + C10
        // =========================
        for (int i = 0; i < 2; i++) {
                *ptr++ = 0xCB;

                uint16_t len = htons(7);
                memcpy(ptr, &len, 2); ptr += 2;

                for (int j = 0; j < 7; j++)
                        *ptr++ = (uint8_t)(j + 1 + i);
        }

        // =========================
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80;

        // STA MAC
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e_rf_tlvs(void)
{
        // C16 + C16
        // =========================
        for (int i = 0; i < 2; i++) {

                *ptr++ = 0xCB;

                uint16_t len = htons(13);
                memcpy(ptr, &len, 2); ptr += 2;

                // Radio MAC
                for (int j = 0; j < 6; j++)
                        *ptr++ = (uint8_t)(0x10 + j + i);

                *ptr++ = 0x80;

                // STA MAC
                for (int j = 0; j < 6; j++)
                        *ptr++ = (uint8_t)(0xA0 + j + i);
        }

        // =========================
        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt16_a_b_c10_d_d_e_rf_tlvs(void)
{
        // ---- TLV 0xCB ----
        *ptr++ = 0xCB;
        *(uint16_t*)ptr = htons(7); ptr += 2;

        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6); ptr += 6;
        *ptr++ = 0x00;

        // D + D  (0x90)
        // =========================
        for (int i = 0; i < 2; i++) {

                *ptr++ = 0x90;

                uint16_t len = htons(12);
                memcpy(ptr, &len, 2); ptr += 2;

                // 12-byte value (example data)
                for (int j = 0; j < 12; j++)
                        *ptr++ = (uint8_t)(0x40 + j + i);
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt17_a_b_c16_d_d_e_rf_tlvs(void)
{
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80;

        // STA MAC
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        // D + D  (0x90)
        // =========================
        for (int i = 0; i < 2; i++) {

                *ptr++ = 0x90;

                uint16_t len = htons(12);
                memcpy(ptr, &len, 2); ptr += 2;

                // 12-byte value (example data)
                for (int j = 0; j < 12; j++)
                        *ptr++ = (uint8_t)(0x40 + j + i);
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e_rf_tlvs(void)
{
        // C10 + C10
        // =========================
        for (int i = 0; i < 2; i++) {

                *ptr++ = 0xCB;

                uint16_t len = htons(7);
                memcpy(ptr, &len, 2); ptr += 2;

                for (int j = 0; j < 7; j++)
                        *ptr++ = (uint8_t)(j + 1 + i);
        }


        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e_rf_tlvs(void)
{
        // C16 + C16
        // =========================
        for (int i = 0; i < 2; i++) {

                *ptr++ = 0xCB;

                uint16_t len = htons(13);
                memcpy(ptr, &len, 2); ptr += 2;

                // Radio MAC (6 bytes)
                for (int j = 0; j < 6; j++)
                        *ptr++ = (uint8_t)(0x10 + j + i);

                *ptr++ = 0x80;

                // STA MAC (6 bytes)
                for (int j = 0; j < 6; j++)
                        *ptr++ = (uint8_t)(0xA0 + j + i);
        }

        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e_rf_tlvs(void)
{
        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        // =========================
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80; // flag

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e_rf_tlvs(void)
{
        // =========================
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80; // flag

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;


        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs(void)
{
        // 3 × C10 TLVs 0xCB
        // =========================
        for (int i = 0; i < 3; i++) {

                *ptr++ = 0xCB; // Type

                uint16_t len = htons(7); // VALUE = 7
                memcpy(ptr, &len, 2);
                ptr += 2;

                // 7 bytes dummy data
                uint8_t val[7];
                for (int j = 0; j < 7; j++) {
                        val[j] = (uint8_t)(j + 1 + i);
                }

                memcpy(ptr, val, 7);
                ptr += 7;
        }
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;


        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e_rf_tlvs(void)
{
        // 3 × C16 TLVs
        // =========================
        for (int i = 0; i < 3; i++) {

                *ptr++ = 0xCB;

                uint16_t len = htons(13);
                memcpy(ptr, &len, 2); ptr += 2;

                // Radio MAC (6 bytes)
                uint8_t radio_mac[6] = {
                        (uint8_t)(0x10 + i),
                        (uint8_t)(0x20 + i),
                        (uint8_t)(0x30 + i),
                        (uint8_t)(0x40 + i),
                        (uint8_t)(0x50 + i),
                        (uint8_t)(0x60 + i)
                };
                memcpy(ptr, radio_mac, 6);
                ptr += 6;

                // Flags
                *ptr++ = 0x80;

                // STA MAC (6 bytes)
                uint8_t sta_mac[6] = {
                        (uint8_t)(0xAA + i),
                        (uint8_t)(0xBB + i),
                        (uint8_t)(0xCC + i),
                        (uint8_t)(0xDD + i),
                        (uint8_t)(0xEE + i),
                        (uint8_t)(0xFF + i)
                };
                memcpy(ptr, sta_mac, 6);
                ptr += 6;
        }

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e_rf_tlvs(void)
{
        // =========================
        // C16
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        // Radio MAC (6 bytes)
        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6);
        ptr += 6;

        *ptr++ = 0x80; // flag

        // STA MAC (6 bytes)
        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6);
        ptr += 6;

        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
        memcpy(ptr, client_mac, 6); ptr += 6;

        uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
        memcpy(ptr, xx_mac, 6); ptr += 6;

        // C10
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int j = 0; j < 7; j++)
                *ptr++ = (uint8_t)(j + 1);

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e_rf_tlvs(void)
{
        // D (0x90)
        // =========================
        *ptr++ = 0x90;

        uint16_t lenD = htons(12);
        memcpy(ptr, &lenD, 2); ptr += 2;

        for (int i = 0; i < 12; i++)
                *ptr++ = (uint8_t)(0x10 + i);

        // =========================
        // C10 (0xCB)
        // =========================
        *ptr++ = 0xCB;

        uint16_t len10 = htons(7);
        memcpy(ptr, &len10, 2); ptr += 2;

        for (int i = 0; i < 7; i++)
                *ptr++ = (uint8_t)(0x20 + i);

        // =========================
        // C16 (0xCB)
        // =========================
        *ptr++ = 0xCB;

        uint16_t len16 = htons(13);
        memcpy(ptr, &len16, 2); ptr += 2;

        uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, radio_mac, 6); ptr += 6;

        *ptr++ = 0x80;

        uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, sta_mac, 6); ptr += 6;

        // =========================
        // D again (0x90)
        // =========================
        *ptr++ = 0x90;

        uint16_t lenD2 = htons(12);
        memcpy(ptr, &lenD2, 2); ptr += 2;

        for (int i = 0; i < 12; i++)
                *ptr++ = (uint8_t)(0x50 + i);

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt1_a_b_c0_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        uint16_t len = htons(0);
        memcpy(ptr, &len, 2);
        ptr += 2;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt2_a_b_c1_e_rb_tlvs(void)
{
        *ptr++ = 0xCB;

        uint16_t len = htons(1);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        *ptr++ = 0x01;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt3_a_b_c2_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 2 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(2);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        *ptr++ = 0x01; *ptr++ = 0x02;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt4_a_b_c3_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 3 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(3);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        *ptr++ = 0x01; *ptr++ = 0x02; *ptr++ = 0x03;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt5_a_b_c4_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 4 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(4);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<4;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt6_a_b_c5_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 5 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(5);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<5;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt7_a_b_c6_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 6 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(6);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<6;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt8_a_b_c8_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 8 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(8);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<8;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt9_a_b_c9_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (L = 9 ❌) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(9);   // ❌ invalid
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<9;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt10_a_b_c10_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB  ----
        *ptr++ = 0xCB;

        uint16_t len = htons(10);   //
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<10;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt11_a_b_c11_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB  ----
        *ptr++ = 0xCB;

        uint16_t len = htons(11);
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<11;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt12_a_b_c12_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB  ----
        *ptr++ = 0xCB;

        uint16_t len = htons(12);
        memcpy(ptr, &len, 2);
        ptr += 2;

        for(int i=0;i<12;i++) *ptr++ = i;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt13_a_b_c20_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (INVALID length=20) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(20);   // ❌ WRONG length
        memcpy(ptr, &len, 2);
        ptr += 2;

        // Put 20 bytes of garbage data
        uint8_t invalid_data[20] = {
                0x10,0x20,0x30,0x40,0x50,0x60,
                0x80, // flag
                0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
                0x01,0x02,0x03,0x04,0x05,0x06,0x07
        };
        memcpy(ptr, invalid_data, 20);
        ptr += 20;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt14_a_b_c15_e_rb_tlvs(void)
{
        // ---- C: TLV 0xCB (INVALID length=15) ----
        *ptr++ = 0xCB;

        uint16_t len = htons(15);   // ❌ WRONG length
        memcpy(ptr, &len, 2);
        ptr += 2;

        // 15 bytes dummy data
        uint8_t invalid_data[15] = {
                0x10,0x20,0x30,0x40,0x50,0x60,
                0x80, // flag
                0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
                0x01,0x02
        };
        memcpy(ptr, invalid_data, 15);
        ptr += 15;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt15_a_b_d0_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(0);
        memcpy(ptr, &len, 2);
        ptr += 2;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt16_a_b_d1_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        uint16_t len = htons(1);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;

        *ptr++ = 0x00; // comment this line to crash get_first_tlv
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt17_a_b_d2_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;
        uint16_t len = htons(2);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00; // comment this line to crash get_first_tlv
        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_handle_bsta_cap_report_pkt18_a_b_d3_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(3);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt19_a_b_d4_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(4);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt20_a_b_d5_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(5);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;


        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt21_a_b_d6_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(6);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt22_a_b_d7_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(7);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt23_a_b_d8_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(8);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt24_a_b_d9_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(9);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt25_a_b_d10_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(10);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt26_a_b_d11_e_rb_tlvs(void)
{
        // ---- TLV 0x90 ----
        *ptr++ = 0x90;

        uint16_t len = htons(11);   // ❌ WRONG (should be 12)
        memcpy(ptr, &len, 2);
        ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt27_a_b_d14_e_rb_tlvs(void)
{
        // ---- TLV 0x90 (INVALID length=14) ----
        *ptr++ = 0x90;

        uint16_t len = htons(14);   // ❌ WRONG
        memcpy(ptr, &len, 2);
        ptr += 2;

        // 14 bytes (overflow case)
        uint8_t data[14] = {
                0x11,0x22,0x33,0x44,0x55,0x66,
                0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
                0x01,0x02
        };
        memcpy(ptr, data, 14);
        ptr += 14;

        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt28_a_b_e_rf_len0_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt29_a_b_e_rb_len1_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(1); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt30_a_b_e_rb_len2_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(2); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt31_a_b_e_rb_len3_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(3); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt32_a_b_e_rb_len4_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(4); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt33_a_b_e_rb_len255_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(255); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt34_a_b_e_rb_tlvs(void)
{
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_handle_bsta_cap_report_pkt35_a_b_c_len0_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_bsta_cap_report_pkt36_a_b_c_len1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_handle_bsta_cap_report_pkt37_a_b_c_len2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_handle_bsta_cap_report_pkt38_a_b_c_len3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_handle_bsta_cap_report_pkt39_a_b_c_len4_rb_tlvs(void)
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

void construct_handle_bsta_cap_report_pkt40_a_b_c_len255_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_handle_bsta_cap_report_pkt41_a_b_c_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_handle_bsta_cap_report_pkt42_a_b_d_len0_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_bsta_cap_report_pkt43_a_b_d_len1_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_handle_bsta_cap_report_pkt44_a_b_d_len2_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_handle_bsta_cap_report_pkt45_a_b_d_len3_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_handle_bsta_cap_report_pkt46_a_b_d_len4_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;


}

void construct_handle_bsta_cap_report_pkt47_a_b_d_len255_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_handle_bsta_cap_report_pkt48_a_b_d_rb_tlvs(void)
{
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_handle_bsta_cap_report_pkt49_a_b_e1_rb_tlvs(void)
{
        *ptr++ = 0x00;
}

void construct_handle_bsta_cap_report_pkt50_a_b_c1_rb_tlvs(void)
{
        *ptr++ = 0xCB;
}

void construct_handle_bsta_cap_report_pkt51_a_b_d1_rb_tlvs(void)
{
        *ptr++ = 0x90;
}


//test_get_first_tlv
void construct_get_first_tlv_pkt1_a_b_e_rb_len0_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_first_tlv_pkt2_a_b_e_rb_len1_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(1); ptr += 2;

}

void construct_get_first_tlv_pkt3_a_b_e_rb_len2_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(2); ptr += 2;

}

void construct_get_first_tlv_pkt4_a_b_e_rb_len3_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(3); ptr += 2;

}

void construct_get_first_tlv_pkt5_a_b_e_rb_len4_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(4); ptr += 2;

}

void construct_get_first_tlv_pkt6_a_b_e_rb_len255_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(255); ptr += 2;

}

void construct_get_first_tlv_pkt7_a_b_e_rb_tlvs(void)
{
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_first_tlv_pkt8_a_b_c_len0_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_get_first_tlv_pkt9_a_b_c_len1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_get_first_tlv_pkt10_a_b_c_len2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_get_first_tlv_pkt11_a_b_c_len3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_get_first_tlv_pkt12_a_b_c_len4_rb_tlvs(void)
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

void construct_get_first_tlv_pkt13_a_b_c_len255_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_get_first_tlv_pkt14_a_b_c_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_get_first_tlv_pkt15_a_b_d_len0_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_get_first_tlv_pkt16_a_b_d_len1_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_get_first_tlv_pkt17_a_b_d_len2_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_get_first_tlv_pkt18_a_b_d_len3_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_get_first_tlv_pkt19_a_b_d_len4_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;


}

void construct_get_first_tlv_pkt20_a_b_d_len255_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_get_first_tlv_pkt21_a_b_d_rb_tlvs(void)
{
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_get_first_tlv_pkt22_a_b_e1_rb_tlvs(void)
{
        *ptr++ = 0x00;
}

void construct_get_first_tlv_pkt23_a_b_c1_rb_tlvs(void)
{
        *ptr++ = 0xCB;
}

void construct_get_first_tlv_pkt24_a_b_d1_rb_tlvs(void)
{
        *ptr++ = 0x90;
}

void construct_get_first_tlv_pkt25_a_b_c_len0_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_first_tlv_pkt26_a_b_c_len1_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_first_tlv_pkt27_a_b_c_len2_e_rb_tlvs(void)
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

void construct_get_first_tlv_pkt28_a_b_c_len3_e3_rb_tlvs(void)
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

void construct_get_first_tlv_pkt29_a_b_c_len4_e3_rb_tlvs(void)
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

void construct_get_first_tlv_pkt30_a_b_c_len5_e3_rb_tlvs(void)
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

void construct_get_first_tlv_pkt31_a_b_c_len6_e3_rb_tlvs(void)
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

void construct_get_first_tlv_pkt32_a_b_c_len7_e3_rb_tlvs(void)
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

void construct_get_first_tlv_pkt33_a_b_c_len8_e3_rb_tlvs(void)
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

void construct_get_first_tlv_pkt34_a_b_c_len0_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_get_first_tlv_pkt35_a_b_c_len1_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;
        *ptr++ = 0xAA;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_first_tlv_pkt36_a_b_c_len2_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_first_tlv_pkt37_a_b_c_len3_e2_rb_tlvs(void)
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

void construct_get_first_tlv_pkt38_a_b_c_len4_e2_rb_tlvs(void)
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

void construct_get_first_tlv_pkt39_a_b_c_len5_e2_rb_tlvs(void)
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

void construct_get_first_tlv_pkt40_a_b_c_len6_e2_rb_tlvs(void)
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

void construct_get_first_tlv_pkt41_a_b_c_len7_e2_rb_tlvs(void)
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

void construct_get_first_tlv_pkt42_a_b_c_len8_e2_rb_tlvs(void)
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

void construct_get_first_tlv_pkt43_a_b_c_len0_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

	*ptr++ = 0x00;

}

void construct_get_first_tlv_pkt44_a_b_c_len1_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;
        *ptr++ = 0xAA;

	*ptr++ = 0x00;

}

void construct_get_first_tlv_pkt45_a_b_c_len2_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

	*ptr++ = 0x00;

}

void construct_get_first_tlv_pkt46_a_b_c_len3_e1_rb_tlvs(void)
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

void construct_get_first_tlv_pkt47_a_b_c_len4_e1_rb_tlvs(void)
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

void construct_get_first_tlv_pkt48_a_b_c_len5_e1_rb_tlvs(void)
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

void construct_get_first_tlv_pkt49_a_b_c_len6_e1_rb_tlvs(void)
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

void construct_get_first_tlv_pkt50_a_b_c_len7_e1_rb_tlvs(void)
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

void construct_get_first_tlv_pkt51_a_b_c_len8_e1_rb_tlvs(void)
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


//test_get_next_tlv(void)
void construct_get_next_tlv_pkt0_a_b_e_rb_len0_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_next_tlv_pkt1_a_b_e_rb_len1_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(1); ptr += 2;

}

void construct_get_next_tlv_pkt2_a_b_e_rb_len2_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(2); ptr += 2;

}

void construct_get_next_tlv_pkt3_a_b_e_rb_len3_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(3); ptr += 2;

}

void construct_get_next_tlv_pkt4_a_b_e_rb_len4_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(4); ptr += 2;

}

void construct_get_next_tlv_pkt5_a_b_e_rb_len255_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(255); ptr += 2;

}

void construct_get_next_tlv_pkt6_a_b_e_rb_tlvs(void)
{
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_next_tlv_pkt7_a_b_c_len0_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_get_next_tlv_pkt8_a_b_c_len1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_get_next_tlv_pkt9_a_b_c_len2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_get_next_tlv_pkt10_a_b_c_len3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_get_next_tlv_pkt11_a_b_c_len4_rb_tlvs(void)
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

void construct_get_next_tlv_pkt12_a_b_c_len255_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_get_next_tlv_pkt13_a_b_c_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_get_next_tlv_pkt14_a_b_d_len0_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_get_next_tlv_pkt15_a_b_d_len1_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

void construct_get_next_tlv_pkt16_a_b_d_len2_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

void construct_get_next_tlv_pkt17_a_b_d_len3_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

void construct_get_next_tlv_pkt18_a_b_d_len4_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;


}

void construct_get_next_tlv_pkt19_a_b_d_len255_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

void construct_get_next_tlv_pkt20_a_b_d_rb_tlvs(void)
{
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

void construct_get_next_tlv_pkt21_a_b_e1_rb_tlvs(void)
{
        *ptr++ = 0x00;
}

void construct_get_next_tlv_pkt22_a_b_c1_rb_tlvs(void)
{
        *ptr++ = 0xCB;
}

void construct_get_next_tlv_pkt23_a_b_d1_rb_tlvs(void)
{
        *ptr++ = 0x90;
}

void construct_get_next_tlv_pkt24_a_b_c_len0_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_next_tlv_pkt25_a_b_c_len1_e3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;

	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_next_tlv_pkt26_a_b_c_len2_e_rb_tlvs(void)
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

void construct_get_next_tlv_pkt27_a_b_c_len3_e3_rb_tlvs(void)
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

void construct_get_next_tlv_pkt28_a_b_c_len4_e3_rb_tlvs(void)
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

void construct_get_next_tlv_pkt29_a_b_c_len5_e3_rb_tlvs(void)
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

void construct_get_next_tlv_pkt30_a_b_c_len6_e3_rb_tlvs(void)
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

void construct_get_next_tlv_pkt31_a_b_c_len7_e3_rb_tlvs(void)
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

void construct_get_next_tlv_pkt32_a_b_c_len8_e3_rb_tlvs(void)
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

void construct_get_next_tlv_pkt33_a_b_c_len0_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

        *(uint16_t*)ptr = htons(0); ptr += 2;
}

void construct_get_next_tlv_pkt34_a_b_c_len1_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;
        *ptr++ = 0xAA;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_next_tlv_pkt35_a_b_c_len2_e2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_get_next_tlv_pkt36_a_b_c_len3_e2_rb_tlvs(void)
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

void construct_get_next_tlv_pkt37_a_b_c_len4_e2_rb_tlvs(void)
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

void construct_get_next_tlv_pkt38_a_b_c_len5_e2_rb_tlvs(void)
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

void construct_get_next_tlv_pkt39_a_b_c_len6_e2_rb_tlvs(void)
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

void construct_get_next_tlv_pkt40_a_b_c_len7_e2_rb_tlvs(void)
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

void construct_get_next_tlv_pkt41_a_b_c_len8_e2_rb_tlvs(void)
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

void construct_get_next_tlv_pkt42_a_b_c_len0_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;

	*ptr++ = 0x00;

}

void construct_get_next_tlv_pkt43_a_b_c_len1_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;
        *ptr++ = 0xAA;

	*ptr++ = 0x00;

}

void construct_get_next_tlv_pkt44_a_b_c_len2_e1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

	*ptr++ = 0x00;

}

void construct_get_next_tlv_pkt45_a_b_c_len3_e1_rb_tlvs(void)
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

void construct_get_next_tlv_pkt46_a_b_c_len4_e1_rb_tlvs(void)
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

void construct_get_next_tlv_pkt47_a_b_c_len5_e1_rb_tlvs(void)
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

void construct_get_next_tlv_pkt48_a_b_c_len6_e1_rb_tlvs(void)
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

void construct_get_next_tlv_pkt49_a_b_c_len7_e1_rb_tlvs(void)
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

void construct_get_next_tlv_pkt50_a_b_c_len8_e1_rb_tlvs(void)
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

void construct_pkt100_a_b_c3_e3_tlvs(void)
{
	        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;


	*ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;
	
}	

void construct_pkt101_a_b_c12_e3_tlvs(void)
{
                // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

	for(int i = 0; i < 9; i++){
                *ptr++ = i;
        }


        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}


void construct_pkt102_a_b_c10_d15_e3_tlvs(void)
{
                // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(7);
        ptr += 2;

        for(int i = 0; i < 7; i++){
                *ptr++ = i;
        }

	*ptr++ = 0x90;

        *(uint16_t*)ptr = htons(12);
        ptr += 2;

        for(int i = 0; i < 12; i++){
                *ptr++ = i;
        }



        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}

void construct_ap_metrics_valid_tlvs(void)
{
    // ✅ AP Metrics TLV (0x94)
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(7);   // ✅ correct length
    ptr += 2;

    // BSSID (6 bytes)
    for (int i = 0; i < 6; i++)
        *ptr++ = i;

    // Channel Utilization (1 byte)
    *ptr++ = 50;

    // EOM
    *ptr++ = 0x00;
    *(uint16_t*)ptr = htons(0);
    ptr += 2;
}

pkt_test_case_t handle_bsta_cap_report_suite[] = {

	{"handle_bsta_cap_report_pkt1_a_b_c10_d_e",             "pkt1.pcap",  construct_handle_bsta_cap_report_pkt1_a_b_c10_d_e_rf_tlvs,             0},
	{"handle_bsta_cap_report_pkt2_a_b_c16_d_e",             "pkt2.pcap",  construct_handle_bsta_cap_report_pkt2_a_b_c16_d_e_rf_tlvs,             0},
	{"handle_bsta_cap_report_pkt4_a_b_c10_e",               "pkt4.pcap",  construct_handle_bsta_cap_report_pkt4_a_b_c10_e_rf_tlvs,               0},
	{"handle_bsta_cap_report_pkt3_a_b_e",                   "pkt3.pcap",  construct_handle_bsta_cap_report_pkt3_a_b_e_rf_tlvs,                   0},
	{"handle_bsta_cap_report_pkt5_a_b_c16_e",               "pkt5.pcap",  construct_handle_bsta_cap_report_pkt5_a_b_c16_e_rf_tlvs,               0},
	{"handle_bsta_cap_report_pkt6_a_b_d_e",                 "pkt6.pcap",  construct_handle_bsta_cap_report_pkt6_a_b_d_e_rf_tlvs,                 0},
	{"handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e",       "pkt7.pcap",  construct_handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e_rf_tlvs,       0},
	{"handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e",   "pkt8.pcap",  construct_handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs,   0},
	{"handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e","pkt9.pcap", construct_handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs, 0},
	{"handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e",    "pkt10.pcap", construct_handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs,    0},
	{"handle_bsta_cap_report_pkt11_a_b_d_d_e",              "pkt11.pcap", construct_handle_bsta_cap_report_pkt11_a_b_d_d_e_rf_tlvs,              0},
	{"handle_bsta_cap_report_pkt12_a_b_c10_c16_e",          "pkt12.pcap", construct_handle_bsta_cap_report_pkt12_a_b_c10_c16_e_rf_tlvs,          0},
	{"handle_bsta_cap_report_pkt13_a_b_c16_c10_e",          "pkt13.pcap", construct_handle_bsta_cap_report_pkt13_a_b_c16_c10_e_rf_tlvs,          0},
	{"handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e",      "pkt14.pcap", construct_handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e_rf_tlvs,      0},
	{"handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e",      "pkt15.pcap", construct_handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e_rf_tlvs,      0},
	{"handle_bsta_cap_report_pkt16_a_b_c10_d_d_e",          "pkt16.pcap", construct_handle_bsta_cap_report_pkt16_a_b_c10_d_d_e_rf_tlvs,          0},
	{"handle_bsta_cap_report_pkt17_a_b_c16_d_d_e",          "pkt17.pcap", construct_handle_bsta_cap_report_pkt17_a_b_c16_d_d_e_rf_tlvs,          0},
	{"handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e",        "pkt18.pcap", construct_handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e_rf_tlvs,        0},
	{"handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e",        "pkt19.pcap", construct_handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e_rf_tlvs,        0},
	{"handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e",        "pkt20.pcap", construct_handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e_rf_tlvs,        0},
	{"handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e",        "pkt21.pcap", construct_handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e_rf_tlvs,        0},
	{"handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e",    "pkt22.pcap", construct_handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs,    0},
	{"handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e",      "pkt23.pcap", construct_handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e_rf_tlvs,      0},
	{"handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e",        "pkt24.pcap", construct_handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e_rf_tlvs,        0},
	{"handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e",      "pkt25.pcap", construct_handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e_rf_tlvs,      0},

	{"handle_bsta_cap_report_pkt1_a_b_c0_e",       "pkt1rb.pcap",  construct_handle_bsta_cap_report_pkt1_a_b_c0_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt2_a_b_c1_e",       "pkt2rb.pcap",  construct_handle_bsta_cap_report_pkt2_a_b_c1_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt3_a_b_c2_e",       "pkt3rb.pcap",  construct_handle_bsta_cap_report_pkt3_a_b_c2_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt4_a_b_c3_e",       "pkt4rb.pcap",  construct_handle_bsta_cap_report_pkt4_a_b_c3_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt5_a_b_c4_e",       "pkt5rb.pcap",  construct_handle_bsta_cap_report_pkt5_a_b_c4_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt6_a_b_c5_e",       "pkt6rb.pcap",  construct_handle_bsta_cap_report_pkt6_a_b_c5_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt7_a_b_c6_e",       "pkt7rb.pcap",  construct_handle_bsta_cap_report_pkt7_a_b_c6_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt8_a_b_c8_e",       "pkt8rb.pcap",  construct_handle_bsta_cap_report_pkt8_a_b_c8_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt9_a_b_c9_e",       "pkt9rb.pcap",  construct_handle_bsta_cap_report_pkt9_a_b_c9_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt10_a_b_c10_e",     "pkt10rb.pcap", construct_handle_bsta_cap_report_pkt10_a_b_c10_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt11_a_b_c11_e",     "pkt11rb.pcap", construct_handle_bsta_cap_report_pkt11_a_b_c11_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt12_a_b_c12_e",     "pkt12rb.pcap", construct_handle_bsta_cap_report_pkt12_a_b_c12_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt13_a_b_c20_e",     "pkt13rb.pcap", construct_handle_bsta_cap_report_pkt13_a_b_c20_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt14_a_b_c15_e",     "pkt14rb.pcap", construct_handle_bsta_cap_report_pkt14_a_b_c15_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt15_a_b_d0_e",      "pkt15rb.pcap", construct_handle_bsta_cap_report_pkt15_a_b_d0_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt16_a_b_d1_e",      "pkt16rb.pcap", construct_handle_bsta_cap_report_pkt16_a_b_d1_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt17_a_b_d2_e",      "pkt17rb.pcap", construct_handle_bsta_cap_report_pkt17_a_b_d2_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt18_a_b_d3_e",      "pkt18rb.pcap", construct_handle_bsta_cap_report_pkt18_a_b_d3_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt19_a_b_d4_e",      "pkt19rb.pcap", construct_handle_bsta_cap_report_pkt19_a_b_d4_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt20_a_b_d5_e",      "pkt20rb.pcap", construct_handle_bsta_cap_report_pkt20_a_b_d5_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt21_a_b_d6_e",      "pkt21rb.pcap", construct_handle_bsta_cap_report_pkt21_a_b_d6_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt22_a_b_d7_e",      "pkt22rb.pcap", construct_handle_bsta_cap_report_pkt22_a_b_d7_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt23_a_b_d8_e",      "pkt23rb.pcap", construct_handle_bsta_cap_report_pkt23_a_b_d8_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt24_a_b_d9_e",      "pkt24rb.pcap", construct_handle_bsta_cap_report_pkt24_a_b_d9_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt25_a_b_d10_e",     "pkt25rb.pcap", construct_handle_bsta_cap_report_pkt25_a_b_d10_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt26_a_b_d11_e",     "pkt26rb.pcap", construct_handle_bsta_cap_report_pkt26_a_b_d11_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt27_a_b_d14_e",     "pkt27rb.pcap", construct_handle_bsta_cap_report_pkt27_a_b_d14_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt28_a_b_e_len0",    "pkt28rf.pcap", construct_handle_bsta_cap_report_pkt28_a_b_e_rf_len0_tlvs,    0},
	{"handle_bsta_cap_report_pkt29_a_b_e_len1",    "pkt29rb.pcap", construct_handle_bsta_cap_report_pkt29_a_b_e_rb_len1_tlvs,    -1},
	{"handle_bsta_cap_report_pkt30_a_b_e_len2",    "pkt30rb.pcap", construct_handle_bsta_cap_report_pkt30_a_b_e_rb_len2_tlvs,    -1},
	{"handle_bsta_cap_report_pkt31_a_b_e_len3",    "pkt31rb.pcap", construct_handle_bsta_cap_report_pkt31_a_b_e_rb_len3_tlvs,    -1},
	{"handle_bsta_cap_report_pkt32_a_b_e_len4",    "pkt32rb.pcap", construct_handle_bsta_cap_report_pkt32_a_b_e_rb_len4_tlvs,    -1},
	{"handle_bsta_cap_report_pkt33_a_b_e_len255",  "pkt33rb.pcap", construct_handle_bsta_cap_report_pkt33_a_b_e_rb_len255_tlvs,  -1},
	{"handle_bsta_cap_report_pkt34_a_b_e",         "pkt34rb.pcap", construct_handle_bsta_cap_report_pkt34_a_b_e_rb_tlvs,         -1},
	{"handle_bsta_cap_report_pkt35_a_b_c_len0",    "pkt35rb.pcap", construct_handle_bsta_cap_report_pkt35_a_b_c_len0_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt36_a_b_c_len1",    "pkt36rb.pcap", construct_handle_bsta_cap_report_pkt36_a_b_c_len1_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt37_a_b_c_len2",    "pkt37rb.pcap", construct_handle_bsta_cap_report_pkt37_a_b_c_len2_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt38_a_b_c_len3",    "pkt38rb.pcap", construct_handle_bsta_cap_report_pkt38_a_b_c_len3_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt39_a_b_c_len4",    "pkt39rb.pcap", construct_handle_bsta_cap_report_pkt39_a_b_c_len4_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt40_a_b_c_len255",  "pkt40rb.pcap", construct_handle_bsta_cap_report_pkt40_a_b_c_len255_rb_tlvs,  -1},
	{"handle_bsta_cap_report_pkt41_a_b_c",         "pkt41rb.pcap", construct_handle_bsta_cap_report_pkt41_a_b_c_rb_tlvs,         -1},
	{"handle_bsta_cap_report_pkt42_a_b_d_len0",    "pkt42rb.pcap", construct_handle_bsta_cap_report_pkt42_a_b_d_len0_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt43_a_b_d_len1",    "pkt43rb.pcap", construct_handle_bsta_cap_report_pkt43_a_b_d_len1_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt44_a_b_d_len2",    "pkt44rb.pcap", construct_handle_bsta_cap_report_pkt44_a_b_d_len2_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt45_a_b_d_len3",    "pkt45rb.pcap", construct_handle_bsta_cap_report_pkt45_a_b_d_len3_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt46_a_b_d_len4",    "pkt46rb.pcap", construct_handle_bsta_cap_report_pkt46_a_b_d_len4_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt47_a_b_d_len255",  "pkt47rb.pcap", construct_handle_bsta_cap_report_pkt47_a_b_d_len255_rb_tlvs,  -1},
	{"handle_bsta_cap_report_pkt48_a_b_d",         "pkt48rb.pcap", construct_handle_bsta_cap_report_pkt48_a_b_d_rb_tlvs,         -1},
	{"handle_bsta_cap_report_pkt49_a_b_e1",        "pkt49rb.pcap", construct_handle_bsta_cap_report_pkt49_a_b_e1_rb_tlvs,        -1},
	{"handle_bsta_cap_report_pkt50_a_b_c1",        "pkt50rb.pcap", construct_handle_bsta_cap_report_pkt50_a_b_c1_rb_tlvs,        -1},
	{"handle_bsta_cap_report_pkt51_a_b_d1",        "pkt51rb.pcap", construct_handle_bsta_cap_report_pkt51_a_b_d1_rb_tlvs,        -1},

	{NULL, NULL, NULL, 0} // Null terminator to mark the end of the array
};

pkt_test_case_t get_first_tlv_suite[] = {

	{"get_first_tlv_pkt1_a_b_e_rb_len0",     "pkt1rb.pcap",  construct_get_first_tlv_pkt1_a_b_e_rb_len0_tlvs,    -1},
	{"get_first_tlv_pkt2_a_b_e_rb_len1",     "pkt2rb.pcap",  construct_get_first_tlv_pkt2_a_b_e_rb_len1_tlvs,    -1},
	{"get_first_tlv_pkt3_a_b_e_rb_len2",     "pkt3rb.pcap",  construct_get_first_tlv_pkt3_a_b_e_rb_len2_tlvs,    -1},
	{"get_first_tlv_pkt4_a_b_e_rb_len3",     "pkt4rb.pcap",  construct_get_first_tlv_pkt4_a_b_e_rb_len3_tlvs,    -1},
	{"get_first_tlv_pkt5_a_b_e_rb_len4",     "pkt5rb.pcap",  construct_get_first_tlv_pkt5_a_b_e_rb_len4_tlvs,    -1},
	{"get_first_tlv_pkt6_a_b_e_rb_len255",   "pkt6rb.pcap",  construct_get_first_tlv_pkt6_a_b_e_rb_len255_tlvs,  -1},
	{"get_first_tlv_pkt7_a_b_e_rb",          "pkt7rb.pcap",  construct_get_first_tlv_pkt7_a_b_e_rb_tlvs,         -1},
	{"get_first_tlv_pkt8_a_b_c_len0_rb",     "pkt8rb.pcap",  construct_get_first_tlv_pkt8_a_b_c_len0_rb_tlvs,    -1},
	{"get_first_tlv_pkt9_a_b_c_len1_rb",     "pkt9rb.pcap",  construct_get_first_tlv_pkt9_a_b_c_len1_rb_tlvs,    0},
	{"get_first_tlv_pkt10_a_b_c_len2_rb",    "pkt10rb.pcap", construct_get_first_tlv_pkt10_a_b_c_len2_rb_tlvs,   0},
	{"get_first_tlv_pkt11_a_b_c_len3_rb",    "pkt11rb.pcap", construct_get_first_tlv_pkt11_a_b_c_len3_rb_tlvs,   0},
	{"get_first_tlv_pkt12_a_b_c_len4_rb",    "pkt12rb.pcap", construct_get_first_tlv_pkt12_a_b_c_len4_rb_tlvs,   0},
	{"get_first_tlv_pkt13_a_b_c_len255_rb",  "pkt13rb.pcap", construct_get_first_tlv_pkt13_a_b_c_len255_rb_tlvs, 0},
	{"get_first_tlv_pkt14_a_b_c_rb",         "pkt14rb.pcap", construct_get_first_tlv_pkt14_a_b_c_rb_tlvs,        -1},
	{"get_first_tlv_pkt15_a_b_d_len0_rb",    "pkt15rb.pcap", construct_get_first_tlv_pkt15_a_b_d_len0_rb_tlvs,   -1},
	{"get_first_tlv_pkt16_a_b_d_len1_rb",    "pkt16rb.pcap", construct_get_first_tlv_pkt16_a_b_d_len1_rb_tlvs,   0},
	{"get_first_tlv_pkt17_a_b_d_len2_rb",    "pkt17rb.pcap", construct_get_first_tlv_pkt17_a_b_d_len2_rb_tlvs,   0},
	{"get_first_tlv_pkt18_a_b_d_len3_rb",    "pkt18rb.pcap", construct_get_first_tlv_pkt18_a_b_d_len3_rb_tlvs,   0},
	{"get_first_tlv_pkt19_a_b_d_len4_rb",    "pkt19rb.pcap", construct_get_first_tlv_pkt19_a_b_d_len4_rb_tlvs,   0},
	{"get_first_tlv_pkt20_a_b_d_len255_rb",  "pkt20rb.pcap", construct_get_first_tlv_pkt20_a_b_d_len255_rb_tlvs, 0},
	{"get_first_tlv_pkt21_a_b_d_rb",         "pkt21rb.pcap", construct_get_first_tlv_pkt21_a_b_d_rb_tlvs,        -1},
	{"get_first_tlv_pkt22_a_b_e1_rb",        "pkt22rb.pcap", construct_get_first_tlv_pkt22_a_b_e1_rb_tlvs,       -1},
	{"get_first_tlv_pkt23_a_b_c1_rb",        "pkt23rb.pcap", construct_get_first_tlv_pkt23_a_b_c1_rb_tlvs,       -1},
	{"get_first_tlv_pkt24_a_b_d1_rb",        "pkt24rb.pcap", construct_get_first_tlv_pkt24_a_b_d1_rb_tlvs,       -1},
	{"get_first_tlv_pkt25_a_b_c_len0_e3_rb", "pkt25rb.pcap", construct_get_first_tlv_pkt25_a_b_c_len0_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt26_a_b_c_len1_e3_rb", "pkt26rb.pcap", construct_get_first_tlv_pkt26_a_b_c_len1_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt27_a_b_c_len2_e_rb",  "pkt27rb.pcap", construct_get_first_tlv_pkt27_a_b_c_len2_e_rb_tlvs,  0},
	{"get_first_tlv_pkt28_a_b_c_len3_e3_rb", "pkt28rb.pcap", construct_get_first_tlv_pkt28_a_b_c_len3_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt29_a_b_c_len4_e3_rb", "pkt29rb.pcap", construct_get_first_tlv_pkt29_a_b_c_len4_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt30_a_b_c_len5_e3_rb", "pkt30rb.pcap", construct_get_first_tlv_pkt30_a_b_c_len5_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt31_a_b_c_len6_e3_rb", "pkt31rb.pcap", construct_get_first_tlv_pkt31_a_b_c_len6_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt32_a_b_c_len7_e3_rb", "pkt32rb.pcap", construct_get_first_tlv_pkt32_a_b_c_len7_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt33_a_b_c_len8_e3_rb", "pkt33rb.pcap", construct_get_first_tlv_pkt33_a_b_c_len8_e3_rb_tlvs, 0},
	{"get_first_tlv_pkt34_a_b_c_len0_e2_rb", "pkt34rb.pcap", construct_get_first_tlv_pkt34_a_b_c_len0_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt35_a_b_c_len1_e2_rb", "pkt35rb.pcap", construct_get_first_tlv_pkt35_a_b_c_len1_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt36_a_b_c_len2_e2_rb", "pkt36rb.pcap", construct_get_first_tlv_pkt36_a_b_c_len2_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt37_a_b_c_len3_e2_rb", "pkt37rb.pcap", construct_get_first_tlv_pkt37_a_b_c_len3_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt38_a_b_c_len4_e2_rb", "pkt38rb.pcap", construct_get_first_tlv_pkt38_a_b_c_len4_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt39_a_b_c_len5_e2_rb", "pkt39rb.pcap", construct_get_first_tlv_pkt39_a_b_c_len5_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt40_a_b_c_len6_e2_rb", "pkt40rb.pcap", construct_get_first_tlv_pkt40_a_b_c_len6_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt41_a_b_c_len7_e2_rb", "pkt41rb.pcap", construct_get_first_tlv_pkt41_a_b_c_len7_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt42_a_b_c_len8_e2_rb", "pkt42rb.pcap", construct_get_first_tlv_pkt42_a_b_c_len8_e2_rb_tlvs, 0},
	{"get_first_tlv_pkt43_a_b_c_len0_e1_rb", "pkt43rb.pcap", construct_get_first_tlv_pkt43_a_b_c_len0_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt44_a_b_c_len1_e1_rb", "pkt44rb.pcap", construct_get_first_tlv_pkt44_a_b_c_len1_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt45_a_b_c_len2_e1_rb", "pkt45rb.pcap", construct_get_first_tlv_pkt45_a_b_c_len2_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt46_a_b_c_len3_e1_rb", "pkt46rb.pcap", construct_get_first_tlv_pkt46_a_b_c_len3_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt47_a_b_c_len4_e1_rb", "pkt47rb.pcap", construct_get_first_tlv_pkt47_a_b_c_len4_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt48_a_b_c_len5_e1_rb", "pkt48rb.pcap", construct_get_first_tlv_pkt48_a_b_c_len5_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt49_a_b_c_len6_e1_rb", "pkt49rb.pcap", construct_get_first_tlv_pkt49_a_b_c_len6_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt50_a_b_c_len7_e1_rb", "pkt50rb.pcap", construct_get_first_tlv_pkt50_a_b_c_len7_e1_rb_tlvs, 0},
	{"get_first_tlv_pkt51_a_b_c_len8_e1_rb", "pkt51rb.pcap", construct_get_first_tlv_pkt51_a_b_c_len8_e1_rb_tlvs, 0},

    {NULL, NULL, NULL, 0}
};

pkt_test_case_t get_next_tlv_suite[] = {

	{"get_next_tlv_pkt0_a_b_e_rb_len0",      "pkt0rb.pcap",  construct_get_next_tlv_pkt0_a_b_e_rb_len0_tlvs,    -1},
	{"get_next_tlv_pkt1_a_b_e_rb_len1",      "pkt1rb.pcap",  construct_get_next_tlv_pkt1_a_b_e_rb_len1_tlvs,    -1},
	{"get_next_tlv_pkt2_a_b_e_rb_len2",      "pkt2rb.pcap",  construct_get_next_tlv_pkt2_a_b_e_rb_len2_tlvs,    -1},
	{"get_next_tlv_pkt3_a_b_e_rb_len3",      "pkt3rb.pcap",  construct_get_next_tlv_pkt3_a_b_e_rb_len3_tlvs,    -1},
	{"get_next_tlv_pkt4_a_b_e_rb_len4",      "pkt4rb.pcap",  construct_get_next_tlv_pkt4_a_b_e_rb_len4_tlvs,    -1},
	{"get_next_tlv_pkt5_a_b_e_rb_len255",    "pkt5rb.pcap",  construct_get_next_tlv_pkt5_a_b_e_rb_len255_tlvs,  -1},
	{"get_next_tlv_pkt6_a_b_e_rb",           "pkt6rb.pcap",  construct_get_next_tlv_pkt6_a_b_e_rb_tlvs,         -1},
	{"get_next_tlv_pkt7_a_b_c_len0_rb",      "pkt7rb.pcap",  construct_get_next_tlv_pkt7_a_b_c_len0_rb_tlvs,    -1},
	{"get_next_tlv_pkt8_a_b_c_len1_rb",      "pkt8rb.pcap",  construct_get_next_tlv_pkt8_a_b_c_len1_rb_tlvs,    -1},
	{"get_next_tlv_pkt9_a_b_c_len2_rb",      "pkt9rb.pcap",  construct_get_next_tlv_pkt9_a_b_c_len2_rb_tlvs,    -1},
	{"get_next_tlv_pkt10_a_b_c_len3_rb",     "pkt10rb.pcap", construct_get_next_tlv_pkt10_a_b_c_len3_rb_tlvs,   -1},
	{"get_next_tlv_pkt11_a_b_c_len4_rb",     "pkt11rb.pcap", construct_get_next_tlv_pkt11_a_b_c_len4_rb_tlvs,   -1},
	{"get_next_tlv_pkt12_a_b_c_len255_rb",   "pkt12rb.pcap", construct_get_next_tlv_pkt12_a_b_c_len255_rb_tlvs, -1},
	{"get_next_tlv_pkt13_a_b_c_rb",          "pkt13rb.pcap", construct_get_next_tlv_pkt13_a_b_c_rb_tlvs,        -1},
	{"get_next_tlv_pkt14_a_b_d_len0_rb",     "pkt14rb.pcap", construct_get_next_tlv_pkt14_a_b_d_len0_rb_tlvs,   -1},
	{"get_next_tlv_pkt15_a_b_d_len1_rb",     "pkt15rb.pcap", construct_get_next_tlv_pkt15_a_b_d_len1_rb_tlvs,   -1},
	{"get_next_tlv_pkt16_a_b_d_len2_rb",     "pkt16rb.pcap", construct_get_next_tlv_pkt16_a_b_d_len2_rb_tlvs,   -1},
	{"get_next_tlv_pkt17_a_b_d_len3_rb",     "pkt17rb.pcap", construct_get_next_tlv_pkt17_a_b_d_len3_rb_tlvs,   -1},
	{"get_next_tlv_pkt18_a_b_d_len4_rb",     "pkt18rb.pcap", construct_get_next_tlv_pkt18_a_b_d_len4_rb_tlvs,   -1},
	{"get_next_tlv_pkt19_a_b_d_len255_rb",   "pkt19rb.pcap", construct_get_next_tlv_pkt19_a_b_d_len255_rb_tlvs, -1},
	{"get_next_tlv_pkt20_a_b_d_rb",          "pkt20rb.pcap", construct_get_next_tlv_pkt20_a_b_d_rb_tlvs,        -1},
	{"get_next_tlv_pkt21_a_b_e1_rb",         "pkt21rb.pcap", construct_get_next_tlv_pkt21_a_b_e1_rb_tlvs,       -1},
	{"get_next_tlv_pkt22_a_b_c1_rb",         "pkt22rb.pcap", construct_get_next_tlv_pkt22_a_b_c1_rb_tlvs,       -1},
	{"get_next_tlv_pkt23_a_b_d1_rb",         "pkt23rb.pcap", construct_get_next_tlv_pkt23_a_b_d1_rb_tlvs,       -1},
	{"get_next_tlv_pkt24_a_b_c_len0_e3_rb",  "pkt24rb.pcap", construct_get_next_tlv_pkt24_a_b_c_len0_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt25_a_b_c_len1_e3_rb",  "pkt25rb.pcap", construct_get_next_tlv_pkt25_a_b_c_len1_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt26_a_b_c_len2_e_rb",   "pkt26rb.pcap", construct_get_next_tlv_pkt26_a_b_c_len2_e_rb_tlvs,  -1},
	{"get_next_tlv_pkt27_a_b_c_len3_e3_rb",  "pkt27rb.pcap", construct_get_next_tlv_pkt27_a_b_c_len3_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt28_a_b_c_len4_e3_rb",  "pkt28rb.pcap", construct_get_next_tlv_pkt28_a_b_c_len4_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt29_a_b_c_len5_e3_rb",  "pkt29rb.pcap", construct_get_next_tlv_pkt29_a_b_c_len5_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt30_a_b_c_len6_e3_rb",  "pkt30rb.pcap", construct_get_next_tlv_pkt30_a_b_c_len6_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt31_a_b_c_len7_e3_rb",  "pkt31rb.pcap", construct_get_next_tlv_pkt31_a_b_c_len7_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt32_a_b_c_len8_e3_rb",  "pkt32rb.pcap", construct_get_next_tlv_pkt32_a_b_c_len8_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt33_a_b_c_len0_e2_rb",  "pkt33rb.pcap", construct_get_next_tlv_pkt33_a_b_c_len0_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt34_a_b_c_len1_e2_rb",  "pkt34rb.pcap", construct_get_next_tlv_pkt34_a_b_c_len1_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt35_a_b_c_len2_e2_rb",  "pkt35rb.pcap", construct_get_next_tlv_pkt35_a_b_c_len2_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt36_a_b_c_len3_e2_rb",  "pkt36rb.pcap", construct_get_next_tlv_pkt36_a_b_c_len3_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt37_a_b_c_len4_e2_rb",  "pkt37rb.pcap", construct_get_next_tlv_pkt37_a_b_c_len4_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt38_a_b_c_len5_e2_rb",  "pkt38rb.pcap", construct_get_next_tlv_pkt38_a_b_c_len5_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt39_a_b_c_len6_e2_rb",  "pkt39rb.pcap", construct_get_next_tlv_pkt39_a_b_c_len6_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt40_a_b_c_len7_e2_rb",  "pkt40rb.pcap", construct_get_next_tlv_pkt40_a_b_c_len7_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt41_a_b_c_len8_e2_rb",  "pkt41rb.pcap", construct_get_next_tlv_pkt41_a_b_c_len8_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt42_a_b_c_len0_e1_rb",  "pkt42rb.pcap", construct_get_next_tlv_pkt42_a_b_c_len0_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt43_a_b_c_len1_e1_rb",  "pkt43rb.pcap", construct_get_next_tlv_pkt43_a_b_c_len1_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt44_a_b_c_len2_e1_rb",  "pkt44rb.pcap", construct_get_next_tlv_pkt44_a_b_c_len2_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt45_a_b_c_len3_e1_rb",  "pkt45rb.pcap", construct_get_next_tlv_pkt45_a_b_c_len3_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt46_a_b_c_len4_e1_rb",  "pkt46rb.pcap", construct_get_next_tlv_pkt46_a_b_c_len4_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt47_a_b_c_len5_e1_rb",  "pkt47rb.pcap", construct_get_next_tlv_pkt47_a_b_c_len5_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt48_a_b_c_len6_e1_rb",  "pkt48rb.pcap", construct_get_next_tlv_pkt48_a_b_c_len6_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt49_a_b_c_len7_e1_rb",  "pkt49rb.pcap", construct_get_next_tlv_pkt49_a_b_c_len7_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt50_a_b_c_len8_e1_rb",  "pkt50rb.pcap", construct_get_next_tlv_pkt50_a_b_c_len8_e1_rb_tlvs, -1},

    {NULL, NULL, NULL, 0}
};

/*
pkt_test_case_t handle_ap_metrics_response_suite[] = {

//	{"pkt7_a_b_c_len0_rb",      "pkt7rb.pcap",  construct_pkt7_a_b_c_len0_rb_tlvs,    -1},
 //       {"pkt34_a_b_c_len0_e2_rb",    "pkt34rb.pcap", construct_pkt34_a_b_c_len0_e2_rb_tlvs,   -1},
	// {"pkt43_a_b_c_len0_e1_rb",   "pkt43rb.pcap", construct_pkt43_a_b_c_len0_e1_rb_tlvs,   -1},

//	 {"pkt21_a_b_e1_rb",         "pkt21rb.pcap", construct_pkt21_a_b_e1_rb_tlvs,       -1},
//         {"pkt22_a_b_c1_rb",         "pkt22rb.pcap", construct_pkt22_a_b_c1_rb_tlvs,       -1},
//	 {"pkt13_a_b_c_rb",          "pkt13rb.pcap", construct_pkt13_a_b_c_rb_tlvs,        -1},
  //       {"pkt6_a_b_e_rb",           "pkt6rb.pcap",  construct_pkt6_a_b_e_rb_tlvs,          -1},
  //       {"pkt100_a_b_c3_e3",       "pkt100.pcap",  construct_pkt100_a_b_c3_e3_tlvs,       0},
    //     {"pkt101_a_b_c12_e3",       "pkt101.pcap", construct_pkt101_a_b_c12_e3_tlvs,      -1},
//	 {"pkt1_a_b_c10_d_e_rf",             "pkt1.pcap",  construct_pkt1_a_b_c10_d_e_rf_tlvs,             0},
//	 {"pkt2_a_b_c16_d_e_rf",             "pkt2.pcap",  construct_pkt2_a_b_c16_d_e_rf_tlvs,             0},
  //       {"pkt102_a_b_c10_d15_e3",             "pkt102.pcap", construct_pkt102_a_b_c10_d15_e3_tlvs,  0},
//	 {"ap_metrics_valid",             "ap.pcap",	construct_ap_metrics_valid_tlvs,  0},

    {NULL, NULL, NULL, 0}
};

*/

pkt_test_case_t handle_ap_metrics_response_suite[] = {

	{"handle_bsta_cap_report_pkt1_a_b_c10_d_e",             "pkt1.pcap",  construct_handle_bsta_cap_report_pkt1_a_b_c10_d_e_rf_tlvs,             -1},
	{"handle_bsta_cap_report_pkt2_a_b_c16_d_e",             "pkt2.pcap",  construct_handle_bsta_cap_report_pkt2_a_b_c16_d_e_rf_tlvs,             -1},
	{"handle_bsta_cap_report_pkt4_a_b_c10_e",               "pkt4.pcap",  construct_handle_bsta_cap_report_pkt4_a_b_c10_e_rf_tlvs,               -1},
	{"handle_bsta_cap_report_pkt3_a_b_e",                   "pkt3.pcap",  construct_handle_bsta_cap_report_pkt3_a_b_e_rf_tlvs,                   -1},
	{"handle_bsta_cap_report_pkt5_a_b_c16_e",               "pkt5.pcap",  construct_handle_bsta_cap_report_pkt5_a_b_c16_e_rf_tlvs,               -1},
	{"handle_bsta_cap_report_pkt6_a_b_d_e",                 "pkt6.pcap",  construct_handle_bsta_cap_report_pkt6_a_b_d_e_rf_tlvs,                 -1},
	{"handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e",       "pkt7.pcap",  construct_handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e_rf_tlvs,       -1},
	{"handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e",   "pkt8.pcap",  construct_handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs,   -1},
	{"handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e","pkt9.pcap", construct_handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs, -1},
	{"handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e",    "pkt10.pcap", construct_handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs,    -1},
	{"handle_bsta_cap_report_pkt11_a_b_d_d_e",              "pkt11.pcap", construct_handle_bsta_cap_report_pkt11_a_b_d_d_e_rf_tlvs,              -1},
	{"handle_bsta_cap_report_pkt12_a_b_c10_c16_e",          "pkt12.pcap", construct_handle_bsta_cap_report_pkt12_a_b_c10_c16_e_rf_tlvs,          -1},
	{"handle_bsta_cap_report_pkt13_a_b_c16_c10_e",          "pkt13.pcap", construct_handle_bsta_cap_report_pkt13_a_b_c16_c10_e_rf_tlvs,          -1},
	{"handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e",      "pkt14.pcap", construct_handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e_rf_tlvs,      -1},
	{"handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e",      "pkt15.pcap", construct_handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e_rf_tlvs,      -1},
	{"handle_bsta_cap_report_pkt16_a_b_c10_d_d_e",          "pkt16.pcap", construct_handle_bsta_cap_report_pkt16_a_b_c10_d_d_e_rf_tlvs,          -1},
	{"handle_bsta_cap_report_pkt17_a_b_c16_d_d_e",          "pkt17.pcap", construct_handle_bsta_cap_report_pkt17_a_b_c16_d_d_e_rf_tlvs,          -1},
	{"handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e",        "pkt18.pcap", construct_handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e_rf_tlvs,        -1},
	{"handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e",        "pkt19.pcap", construct_handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e_rf_tlvs,        -1},
	{"handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e",        "pkt20.pcap", construct_handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e_rf_tlvs,        -1},
	{"handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e",        "pkt21.pcap", construct_handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e_rf_tlvs,        -1},
	{"handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e",    "pkt22.pcap", construct_handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs,    -1},
	{"handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e",      "pkt23.pcap", construct_handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e_rf_tlvs,      -1},
	{"handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e",        "pkt24.pcap", construct_handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e_rf_tlvs,        -1},
	{"handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e",      "pkt25.pcap", construct_handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e_rf_tlvs,      -1},

	{"handle_bsta_cap_report_pkt1_a_b_c0_e",       "pkt1rb.pcap",  construct_handle_bsta_cap_report_pkt1_a_b_c0_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt2_a_b_c1_e",       "pkt2rb.pcap",  construct_handle_bsta_cap_report_pkt2_a_b_c1_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt3_a_b_c2_e",       "pkt3rb.pcap",  construct_handle_bsta_cap_report_pkt3_a_b_c2_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt4_a_b_c3_e",       "pkt4rb.pcap",  construct_handle_bsta_cap_report_pkt4_a_b_c3_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt5_a_b_c4_e",       "pkt5rb.pcap",  construct_handle_bsta_cap_report_pkt5_a_b_c4_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt6_a_b_c5_e",       "pkt6rb.pcap",  construct_handle_bsta_cap_report_pkt6_a_b_c5_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt7_a_b_c6_e",       "pkt7rb.pcap",  construct_handle_bsta_cap_report_pkt7_a_b_c6_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt8_a_b_c8_e",       "pkt8rb.pcap",  construct_handle_bsta_cap_report_pkt8_a_b_c8_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt9_a_b_c9_e",       "pkt9rb.pcap",  construct_handle_bsta_cap_report_pkt9_a_b_c9_e_rb_tlvs,       -1},
	{"handle_bsta_cap_report_pkt10_a_b_c10_e",     "pkt10rb.pcap", construct_handle_bsta_cap_report_pkt10_a_b_c10_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt11_a_b_c11_e",     "pkt11rb.pcap", construct_handle_bsta_cap_report_pkt11_a_b_c11_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt12_a_b_c12_e",     "pkt12rb.pcap", construct_handle_bsta_cap_report_pkt12_a_b_c12_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt13_a_b_c20_e",     "pkt13rb.pcap", construct_handle_bsta_cap_report_pkt13_a_b_c20_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt14_a_b_c15_e",     "pkt14rb.pcap", construct_handle_bsta_cap_report_pkt14_a_b_c15_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt15_a_b_d0_e",      "pkt15rb.pcap", construct_handle_bsta_cap_report_pkt15_a_b_d0_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt16_a_b_d1_e",      "pkt16rb.pcap", construct_handle_bsta_cap_report_pkt16_a_b_d1_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt17_a_b_d2_e",      "pkt17rb.pcap", construct_handle_bsta_cap_report_pkt17_a_b_d2_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt18_a_b_d3_e",      "pkt18rb.pcap", construct_handle_bsta_cap_report_pkt18_a_b_d3_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt19_a_b_d4_e",      "pkt19rb.pcap", construct_handle_bsta_cap_report_pkt19_a_b_d4_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt20_a_b_d5_e",      "pkt20rb.pcap", construct_handle_bsta_cap_report_pkt20_a_b_d5_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt21_a_b_d6_e",      "pkt21rb.pcap", construct_handle_bsta_cap_report_pkt21_a_b_d6_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt22_a_b_d7_e",      "pkt22rb.pcap", construct_handle_bsta_cap_report_pkt22_a_b_d7_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt23_a_b_d8_e",      "pkt23rb.pcap", construct_handle_bsta_cap_report_pkt23_a_b_d8_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt24_a_b_d9_e",      "pkt24rb.pcap", construct_handle_bsta_cap_report_pkt24_a_b_d9_e_rb_tlvs,      -1},
	{"handle_bsta_cap_report_pkt25_a_b_d10_e",     "pkt25rb.pcap", construct_handle_bsta_cap_report_pkt25_a_b_d10_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt26_a_b_d11_e",     "pkt26rb.pcap", construct_handle_bsta_cap_report_pkt26_a_b_d11_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt27_a_b_d14_e",     "pkt27rb.pcap", construct_handle_bsta_cap_report_pkt27_a_b_d14_e_rb_tlvs,     -1},
	{"handle_bsta_cap_report_pkt28_a_b_e_len0",    "pkt28rf.pcap", construct_handle_bsta_cap_report_pkt28_a_b_e_rf_len0_tlvs,    -1},
	{"handle_bsta_cap_report_pkt29_a_b_e_len1",    "pkt29rb.pcap", construct_handle_bsta_cap_report_pkt29_a_b_e_rb_len1_tlvs,    -1},
	{"handle_bsta_cap_report_pkt30_a_b_e_len2",    "pkt30rb.pcap", construct_handle_bsta_cap_report_pkt30_a_b_e_rb_len2_tlvs,    -1},
	{"handle_bsta_cap_report_pkt31_a_b_e_len3",    "pkt31rb.pcap", construct_handle_bsta_cap_report_pkt31_a_b_e_rb_len3_tlvs,    -1},
	{"handle_bsta_cap_report_pkt32_a_b_e_len4",    "pkt32rb.pcap", construct_handle_bsta_cap_report_pkt32_a_b_e_rb_len4_tlvs,    -1},
	{"handle_bsta_cap_report_pkt33_a_b_e_len255",  "pkt33rb.pcap", construct_handle_bsta_cap_report_pkt33_a_b_e_rb_len255_tlvs,  -1},
	{"handle_bsta_cap_report_pkt34_a_b_e",         "pkt34rb.pcap", construct_handle_bsta_cap_report_pkt34_a_b_e_rb_tlvs,         -1},
	{"handle_bsta_cap_report_pkt35_a_b_c_len0",    "pkt35rb.pcap", construct_handle_bsta_cap_report_pkt35_a_b_c_len0_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt36_a_b_c_len1",    "pkt36rb.pcap", construct_handle_bsta_cap_report_pkt36_a_b_c_len1_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt37_a_b_c_len2",    "pkt37rb.pcap", construct_handle_bsta_cap_report_pkt37_a_b_c_len2_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt38_a_b_c_len3",    "pkt38rb.pcap", construct_handle_bsta_cap_report_pkt38_a_b_c_len3_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt39_a_b_c_len4",    "pkt39rb.pcap", construct_handle_bsta_cap_report_pkt39_a_b_c_len4_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt40_a_b_c_len255",  "pkt40rb.pcap", construct_handle_bsta_cap_report_pkt40_a_b_c_len255_rb_tlvs,  -1},
	{"handle_bsta_cap_report_pkt41_a_b_c",         "pkt41rb.pcap", construct_handle_bsta_cap_report_pkt41_a_b_c_rb_tlvs,         -1},
	{"handle_bsta_cap_report_pkt42_a_b_d_len0",    "pkt42rb.pcap", construct_handle_bsta_cap_report_pkt42_a_b_d_len0_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt43_a_b_d_len1",    "pkt43rb.pcap", construct_handle_bsta_cap_report_pkt43_a_b_d_len1_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt44_a_b_d_len2",    "pkt44rb.pcap", construct_handle_bsta_cap_report_pkt44_a_b_d_len2_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt45_a_b_d_len3",    "pkt45rb.pcap", construct_handle_bsta_cap_report_pkt45_a_b_d_len3_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt46_a_b_d_len4",    "pkt46rb.pcap", construct_handle_bsta_cap_report_pkt46_a_b_d_len4_rb_tlvs,    -1},
	{"handle_bsta_cap_report_pkt47_a_b_d_len255",  "pkt47rb.pcap", construct_handle_bsta_cap_report_pkt47_a_b_d_len255_rb_tlvs,  -1},
	{"handle_bsta_cap_report_pkt48_a_b_d",         "pkt48rb.pcap", construct_handle_bsta_cap_report_pkt48_a_b_d_rb_tlvs,         -1},
	{"handle_bsta_cap_report_pkt49_a_b_e1",        "pkt49rb.pcap", construct_handle_bsta_cap_report_pkt49_a_b_e1_rb_tlvs,        -1},
	{"handle_bsta_cap_report_pkt50_a_b_c1",        "pkt50rb.pcap", construct_handle_bsta_cap_report_pkt50_a_b_c1_rb_tlvs,        -1},
	{"handle_bsta_cap_report_pkt51_a_b_d1",        "pkt51rb.pcap", construct_handle_bsta_cap_report_pkt51_a_b_d1_rb_tlvs,        -1},

	{"get_first_tlv_pkt1_a_b_e_rb_len0",     "pkt1rb.pcap",  construct_get_first_tlv_pkt1_a_b_e_rb_len0_tlvs,    -1},
	{"get_first_tlv_pkt2_a_b_e_rb_len1",     "pkt2rb.pcap",  construct_get_first_tlv_pkt2_a_b_e_rb_len1_tlvs,    -1},
	{"get_first_tlv_pkt3_a_b_e_rb_len2",     "pkt3rb.pcap",  construct_get_first_tlv_pkt3_a_b_e_rb_len2_tlvs,    -1},
	{"get_first_tlv_pkt4_a_b_e_rb_len3",     "pkt4rb.pcap",  construct_get_first_tlv_pkt4_a_b_e_rb_len3_tlvs,    -1},
	{"get_first_tlv_pkt5_a_b_e_rb_len4",     "pkt5rb.pcap",  construct_get_first_tlv_pkt5_a_b_e_rb_len4_tlvs,    -1},
	{"get_first_tlv_pkt6_a_b_e_rb_len255",   "pkt6rb.pcap",  construct_get_first_tlv_pkt6_a_b_e_rb_len255_tlvs,  -1},
	{"get_first_tlv_pkt7_a_b_e_rb",          "pkt7rb.pcap",  construct_get_first_tlv_pkt7_a_b_e_rb_tlvs,         -1},
	{"get_first_tlv_pkt8_a_b_c_len0_rb",     "pkt8rb.pcap",  construct_get_first_tlv_pkt8_a_b_c_len0_rb_tlvs,    -1},
	{"get_first_tlv_pkt9_a_b_c_len1_rb",     "pkt9rb.pcap",  construct_get_first_tlv_pkt9_a_b_c_len1_rb_tlvs,    -1},
	{"get_first_tlv_pkt10_a_b_c_len2_rb",    "pkt10rb.pcap", construct_get_first_tlv_pkt10_a_b_c_len2_rb_tlvs,   -1},
	{"get_first_tlv_pkt11_a_b_c_len3_rb",    "pkt11rb.pcap", construct_get_first_tlv_pkt11_a_b_c_len3_rb_tlvs,   -1},
	{"get_first_tlv_pkt12_a_b_c_len4_rb",    "pkt12rb.pcap", construct_get_first_tlv_pkt12_a_b_c_len4_rb_tlvs,   -1},
	{"get_first_tlv_pkt13_a_b_c_len255_rb",  "pkt13rb.pcap", construct_get_first_tlv_pkt13_a_b_c_len255_rb_tlvs, -1},
	{"get_first_tlv_pkt14_a_b_c_rb",         "pkt14rb.pcap", construct_get_first_tlv_pkt14_a_b_c_rb_tlvs,        -1},
	{"get_first_tlv_pkt15_a_b_d_len0_rb",    "pkt15rb.pcap", construct_get_first_tlv_pkt15_a_b_d_len0_rb_tlvs,   -1},
	{"get_first_tlv_pkt16_a_b_d_len1_rb",    "pkt16rb.pcap", construct_get_first_tlv_pkt16_a_b_d_len1_rb_tlvs,   -1},
	{"get_first_tlv_pkt17_a_b_d_len2_rb",    "pkt17rb.pcap", construct_get_first_tlv_pkt17_a_b_d_len2_rb_tlvs,   -1},
	{"get_first_tlv_pkt18_a_b_d_len3_rb",    "pkt18rb.pcap", construct_get_first_tlv_pkt18_a_b_d_len3_rb_tlvs,   -1},
	{"get_first_tlv_pkt19_a_b_d_len4_rb",    "pkt19rb.pcap", construct_get_first_tlv_pkt19_a_b_d_len4_rb_tlvs,   -1},
	{"get_first_tlv_pkt20_a_b_d_len255_rb",  "pkt20rb.pcap", construct_get_first_tlv_pkt20_a_b_d_len255_rb_tlvs, -1},
	{"get_first_tlv_pkt21_a_b_d_rb",         "pkt21rb.pcap", construct_get_first_tlv_pkt21_a_b_d_rb_tlvs,        -1},
	{"get_first_tlv_pkt22_a_b_e1_rb",        "pkt22rb.pcap", construct_get_first_tlv_pkt22_a_b_e1_rb_tlvs,       -1},
	{"get_first_tlv_pkt23_a_b_c1_rb",        "pkt23rb.pcap", construct_get_first_tlv_pkt23_a_b_c1_rb_tlvs,       -1},
	{"get_first_tlv_pkt24_a_b_d1_rb",        "pkt24rb.pcap", construct_get_first_tlv_pkt24_a_b_d1_rb_tlvs,       -1},
	{"get_first_tlv_pkt25_a_b_c_len0_e3_rb", "pkt25rb.pcap", construct_get_first_tlv_pkt25_a_b_c_len0_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt26_a_b_c_len1_e3_rb", "pkt26rb.pcap", construct_get_first_tlv_pkt26_a_b_c_len1_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt27_a_b_c_len2_e_rb",  "pkt27rb.pcap", construct_get_first_tlv_pkt27_a_b_c_len2_e_rb_tlvs,  -1},
	{"get_first_tlv_pkt28_a_b_c_len3_e3_rb", "pkt28rb.pcap", construct_get_first_tlv_pkt28_a_b_c_len3_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt29_a_b_c_len4_e3_rb", "pkt29rb.pcap", construct_get_first_tlv_pkt29_a_b_c_len4_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt30_a_b_c_len5_e3_rb", "pkt30rb.pcap", construct_get_first_tlv_pkt30_a_b_c_len5_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt31_a_b_c_len6_e3_rb", "pkt31rb.pcap", construct_get_first_tlv_pkt31_a_b_c_len6_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt32_a_b_c_len7_e3_rb", "pkt32rb.pcap", construct_get_first_tlv_pkt32_a_b_c_len7_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt33_a_b_c_len8_e3_rb", "pkt33rb.pcap", construct_get_first_tlv_pkt33_a_b_c_len8_e3_rb_tlvs, -1},
	{"get_first_tlv_pkt34_a_b_c_len0_e2_rb", "pkt34rb.pcap", construct_get_first_tlv_pkt34_a_b_c_len0_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt35_a_b_c_len1_e2_rb", "pkt35rb.pcap", construct_get_first_tlv_pkt35_a_b_c_len1_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt36_a_b_c_len2_e2_rb", "pkt36rb.pcap", construct_get_first_tlv_pkt36_a_b_c_len2_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt37_a_b_c_len3_e2_rb", "pkt37rb.pcap", construct_get_first_tlv_pkt37_a_b_c_len3_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt38_a_b_c_len4_e2_rb", "pkt38rb.pcap", construct_get_first_tlv_pkt38_a_b_c_len4_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt39_a_b_c_len5_e2_rb", "pkt39rb.pcap", construct_get_first_tlv_pkt39_a_b_c_len5_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt40_a_b_c_len6_e2_rb", "pkt40rb.pcap", construct_get_first_tlv_pkt40_a_b_c_len6_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt41_a_b_c_len7_e2_rb", "pkt41rb.pcap", construct_get_first_tlv_pkt41_a_b_c_len7_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt42_a_b_c_len8_e2_rb", "pkt42rb.pcap", construct_get_first_tlv_pkt42_a_b_c_len8_e2_rb_tlvs, -1},
	{"get_first_tlv_pkt43_a_b_c_len0_e1_rb", "pkt43rb.pcap", construct_get_first_tlv_pkt43_a_b_c_len0_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt44_a_b_c_len1_e1_rb", "pkt44rb.pcap", construct_get_first_tlv_pkt44_a_b_c_len1_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt45_a_b_c_len2_e1_rb", "pkt45rb.pcap", construct_get_first_tlv_pkt45_a_b_c_len2_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt46_a_b_c_len3_e1_rb", "pkt46rb.pcap", construct_get_first_tlv_pkt46_a_b_c_len3_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt47_a_b_c_len4_e1_rb", "pkt47rb.pcap", construct_get_first_tlv_pkt47_a_b_c_len4_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt48_a_b_c_len5_e1_rb", "pkt48rb.pcap", construct_get_first_tlv_pkt48_a_b_c_len5_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt49_a_b_c_len6_e1_rb", "pkt49rb.pcap", construct_get_first_tlv_pkt49_a_b_c_len6_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt50_a_b_c_len7_e1_rb", "pkt50rb.pcap", construct_get_first_tlv_pkt50_a_b_c_len7_e1_rb_tlvs, -1},
	{"get_first_tlv_pkt51_a_b_c_len8_e1_rb", "pkt51rb.pcap", construct_get_first_tlv_pkt51_a_b_c_len8_e1_rb_tlvs, -1},

	{"get_next_tlv_pkt0_a_b_e_rb_len0",      "pkt0rb.pcap",  construct_get_next_tlv_pkt0_a_b_e_rb_len0_tlvs,    -1},
	{"get_next_tlv_pkt1_a_b_e_rb_len1",      "pkt1rb.pcap",  construct_get_next_tlv_pkt1_a_b_e_rb_len1_tlvs,    -1},
	{"get_next_tlv_pkt2_a_b_e_rb_len2",      "pkt2rb.pcap",  construct_get_next_tlv_pkt2_a_b_e_rb_len2_tlvs,    -1},
	{"get_next_tlv_pkt3_a_b_e_rb_len3",      "pkt3rb.pcap",  construct_get_next_tlv_pkt3_a_b_e_rb_len3_tlvs,    -1},
	{"get_next_tlv_pkt4_a_b_e_rb_len4",      "pkt4rb.pcap",  construct_get_next_tlv_pkt4_a_b_e_rb_len4_tlvs,    -1},
	{"get_next_tlv_pkt5_a_b_e_rb_len255",    "pkt5rb.pcap",  construct_get_next_tlv_pkt5_a_b_e_rb_len255_tlvs,  -1},
	{"get_next_tlv_pkt6_a_b_e_rb",           "pkt6rb.pcap",  construct_get_next_tlv_pkt6_a_b_e_rb_tlvs,         -1},
	{"get_next_tlv_pkt7_a_b_c_len0_rb",      "pkt7rb.pcap",  construct_get_next_tlv_pkt7_a_b_c_len0_rb_tlvs,    -1},
	{"get_next_tlv_pkt8_a_b_c_len1_rb",      "pkt8rb.pcap",  construct_get_next_tlv_pkt8_a_b_c_len1_rb_tlvs,    -1},
	{"get_next_tlv_pkt9_a_b_c_len2_rb",      "pkt9rb.pcap",  construct_get_next_tlv_pkt9_a_b_c_len2_rb_tlvs,    -1},
	{"get_next_tlv_pkt10_a_b_c_len3_rb",     "pkt10rb.pcap", construct_get_next_tlv_pkt10_a_b_c_len3_rb_tlvs,   -1},
	{"get_next_tlv_pkt11_a_b_c_len4_rb",     "pkt11rb.pcap", construct_get_next_tlv_pkt11_a_b_c_len4_rb_tlvs,   -1},
	{"get_next_tlv_pkt12_a_b_c_len255_rb",   "pkt12rb.pcap", construct_get_next_tlv_pkt12_a_b_c_len255_rb_tlvs, -1},
	{"get_next_tlv_pkt13_a_b_c_rb",          "pkt13rb.pcap", construct_get_next_tlv_pkt13_a_b_c_rb_tlvs,        -1},
	{"get_next_tlv_pkt14_a_b_d_len0_rb",     "pkt14rb.pcap", construct_get_next_tlv_pkt14_a_b_d_len0_rb_tlvs,   -1},
	{"get_next_tlv_pkt15_a_b_d_len1_rb",     "pkt15rb.pcap", construct_get_next_tlv_pkt15_a_b_d_len1_rb_tlvs,   -1},
	{"get_next_tlv_pkt16_a_b_d_len2_rb",     "pkt16rb.pcap", construct_get_next_tlv_pkt16_a_b_d_len2_rb_tlvs,   -1},
	{"get_next_tlv_pkt17_a_b_d_len3_rb",     "pkt17rb.pcap", construct_get_next_tlv_pkt17_a_b_d_len3_rb_tlvs,   -1},
	{"get_next_tlv_pkt18_a_b_d_len4_rb",     "pkt18rb.pcap", construct_get_next_tlv_pkt18_a_b_d_len4_rb_tlvs,   -1},
	{"get_next_tlv_pkt19_a_b_d_len255_rb",   "pkt19rb.pcap", construct_get_next_tlv_pkt19_a_b_d_len255_rb_tlvs, -1},
	{"get_next_tlv_pkt20_a_b_d_rb",          "pkt20rb.pcap", construct_get_next_tlv_pkt20_a_b_d_rb_tlvs,        -1},
	{"get_next_tlv_pkt21_a_b_e1_rb",         "pkt21rb.pcap", construct_get_next_tlv_pkt21_a_b_e1_rb_tlvs,       -1},
	{"get_next_tlv_pkt22_a_b_c1_rb",         "pkt22rb.pcap", construct_get_next_tlv_pkt22_a_b_c1_rb_tlvs,       -1},
	{"get_next_tlv_pkt23_a_b_d1_rb",         "pkt23rb.pcap", construct_get_next_tlv_pkt23_a_b_d1_rb_tlvs,       -1},
	{"get_next_tlv_pkt24_a_b_c_len0_e3_rb",  "pkt24rb.pcap", construct_get_next_tlv_pkt24_a_b_c_len0_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt25_a_b_c_len1_e3_rb",  "pkt25rb.pcap", construct_get_next_tlv_pkt25_a_b_c_len1_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt26_a_b_c_len2_e_rb",   "pkt26rb.pcap", construct_get_next_tlv_pkt26_a_b_c_len2_e_rb_tlvs,  -1},
	{"get_next_tlv_pkt27_a_b_c_len3_e3_rb",  "pkt27rb.pcap", construct_get_next_tlv_pkt27_a_b_c_len3_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt28_a_b_c_len4_e3_rb",  "pkt28rb.pcap", construct_get_next_tlv_pkt28_a_b_c_len4_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt29_a_b_c_len5_e3_rb",  "pkt29rb.pcap", construct_get_next_tlv_pkt29_a_b_c_len5_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt30_a_b_c_len6_e3_rb",  "pkt30rb.pcap", construct_get_next_tlv_pkt30_a_b_c_len6_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt31_a_b_c_len7_e3_rb",  "pkt31rb.pcap", construct_get_next_tlv_pkt31_a_b_c_len7_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt32_a_b_c_len8_e3_rb",  "pkt32rb.pcap", construct_get_next_tlv_pkt32_a_b_c_len8_e3_rb_tlvs, -1},
	{"get_next_tlv_pkt33_a_b_c_len0_e2_rb",  "pkt33rb.pcap", construct_get_next_tlv_pkt33_a_b_c_len0_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt34_a_b_c_len1_e2_rb",  "pkt34rb.pcap", construct_get_next_tlv_pkt34_a_b_c_len1_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt35_a_b_c_len2_e2_rb",  "pkt35rb.pcap", construct_get_next_tlv_pkt35_a_b_c_len2_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt36_a_b_c_len3_e2_rb",  "pkt36rb.pcap", construct_get_next_tlv_pkt36_a_b_c_len3_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt37_a_b_c_len4_e2_rb",  "pkt37rb.pcap", construct_get_next_tlv_pkt37_a_b_c_len4_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt38_a_b_c_len5_e2_rb",  "pkt38rb.pcap", construct_get_next_tlv_pkt38_a_b_c_len5_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt39_a_b_c_len6_e2_rb",  "pkt39rb.pcap", construct_get_next_tlv_pkt39_a_b_c_len6_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt40_a_b_c_len7_e2_rb",  "pkt40rb.pcap", construct_get_next_tlv_pkt40_a_b_c_len7_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt41_a_b_c_len8_e2_rb",  "pkt41rb.pcap", construct_get_next_tlv_pkt41_a_b_c_len8_e2_rb_tlvs, -1},
	{"get_next_tlv_pkt42_a_b_c_len0_e1_rb",  "pkt42rb.pcap", construct_get_next_tlv_pkt42_a_b_c_len0_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt43_a_b_c_len1_e1_rb",  "pkt43rb.pcap", construct_get_next_tlv_pkt43_a_b_c_len1_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt44_a_b_c_len2_e1_rb",  "pkt44rb.pcap", construct_get_next_tlv_pkt44_a_b_c_len2_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt45_a_b_c_len3_e1_rb",  "pkt45rb.pcap", construct_get_next_tlv_pkt45_a_b_c_len3_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt46_a_b_c_len4_e1_rb",  "pkt46rb.pcap", construct_get_next_tlv_pkt46_a_b_c_len4_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt47_a_b_c_len5_e1_rb",  "pkt47rb.pcap", construct_get_next_tlv_pkt47_a_b_c_len5_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt48_a_b_c_len6_e1_rb",  "pkt48rb.pcap", construct_get_next_tlv_pkt48_a_b_c_len6_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt49_a_b_c_len7_e1_rb",  "pkt49rb.pcap", construct_get_next_tlv_pkt49_a_b_c_len7_e1_rb_tlvs, -1},
	{"get_next_tlv_pkt50_a_b_c_len8_e1_rb",  "pkt50rb.pcap", construct_get_next_tlv_pkt50_a_b_c_len8_e1_rb_tlvs, -1},

	{NULL, NULL, NULL, 0}
};
