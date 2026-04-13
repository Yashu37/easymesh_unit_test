void construct_ap_metrics_tlv_a_b_f_e_rf(void)
{
    // ---- F: AP Metrics TLV (0x94)
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(7);   // 6 (BSSID) + 1 (Channel Utilization)
    ptr += 2;

    // BSSID (6 bytes)
    for (int i = 0; i < 6; i++) {
        *ptr++ = i;
    }

    // Channel Utilization (1 byte)
    *ptr++ = 0x50;

    // ---- EOM TLV (End Of Message)
    *ptr++ = 0x00;   // Type
    *ptr++ = 0x00;   // Length MSB
    *ptr++ = 0x00;   // Length LSB
}


void construct_ap_metrics_tlv_a_b_f_e_rb_len0(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(0);
    ptr += 2;

    // no value

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len1(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(1);
    ptr += 2;

    *ptr++ = 0xAA;  // partial data

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len2(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(2);
    ptr += 2;

    for (int i = 0; i < 2; i++) {
        *ptr++ = i;
    }

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len3(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(3);
    ptr += 2;

    for (int i = 0; i < 3; i++) {
        *ptr++ = i;
    }

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len4(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(4);
    ptr += 2;

    for (int i = 0; i < 4; i++) {
        *ptr++ = i;
    }

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len5(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(5);
    ptr += 2;

    for (int i = 0; i < 5; i++) {
        *ptr++ = i;
    }

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len6(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(6);
    ptr += 2;

    // only BSSID, missing channel utilization
    for (int i = 0; i < 6; i++) {
        *ptr++ = i;
    }

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}

void construct_ap_metrics_tlv_a_b_f_e_rb_len8(void)
{
    *ptr++ = 0x94;

    *(uint16_t*)ptr = htons(8);   // ❌ invalid
    ptr += 2;

    // BSSID (6 bytes)
    for (int i = 0; i < 6; i++) {
        *ptr++ = i;
    }

    // Channel Utilization
    *ptr++ = 0x50;

    // Extra byte (invalid)
    *ptr++ = 0xFF;

    // ---- EOM
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
}
