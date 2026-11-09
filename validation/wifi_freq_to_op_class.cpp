/*
 * HANDLER: wifi_freq_to_op_class
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:920-930 (~/Desktop/G/rdk-wifi-hal), together with its only dependency, the REAL
 * ieee80211_freq_to_channel_ext copied verbatim from hostap-2.10 (~/Desktop/G/rdk-wifi-libhostap/source/hostap-2.10/src/common/ieee802_11_common.c:898-1124).
 * This file holds the ORIGINAL code: no fix is applied (the function is pure; no finding).  Renamed hwr_wifi_freq_to_op_class because the other
 * platforms define the same name.
 *
 * Scaffolding only: the u8 / enum hostapd_hw_mode / CHANWIDTH_* definitions the hostap function needs (values from hostap defs.h and
 * ieee802_11_defs.h), and the print macro mapped to the log sink hwr_print (runner-poisoned slot).  wifi_freq_to_op_class always passes
 * sec_channel 0 and chanwidth 0 (CHANWIDTH_USE_HT).
 */
#include "hwr_fco.h"
#include <stdio.h>

typedef unsigned char u8;
enum hostapd_hw_mode { HOSTAPD_MODE_IEEE80211B, HOSTAPD_MODE_IEEE80211G, HOSTAPD_MODE_IEEE80211A, HOSTAPD_MODE_IEEE80211AD, HOSTAPD_MODE_IEEE80211ANY, NUM_HOSTAPD_MODES };
#define CHANWIDTH_USE_HT	0
#define CHANWIDTH_80MHZ		1
#define CHANWIDTH_160MHZ	2
#define CHANWIDTH_80P80MHZ	3
#define CHANWIDTH_2160MHZ	4
#define CHANWIDTH_4320MHZ	5
#define CHANWIDTH_6480MHZ	6
#define CHANWIDTH_8640MHZ	7

#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_freq_to_op_class hwr_wifi_freq_to_op_class

/* --- hostap-2.10 ieee802_11_common.c:898-1124 --- */
static enum hostapd_hw_mode ieee80211_freq_to_channel_ext(unsigned int freq,
						   int sec_channel,
						   int chanwidth,
						   u8 *op_class, u8 *channel)
{
	u8 vht_opclass;

	/* TODO: more operating classes */

	if (sec_channel > 1 || sec_channel < -1)
		return NUM_HOSTAPD_MODES;

	if (freq >= 2412 && freq <= 2472) {
		if ((freq - 2407) % 5)
			return NUM_HOSTAPD_MODES;

		if (chanwidth)
			return NUM_HOSTAPD_MODES;

		/* 2.407 GHz, channels 1..13 */
		if (sec_channel == 1)
			*op_class = 83;
		else if (sec_channel == -1)
			*op_class = 84;
		else
			*op_class = 81;

		*channel = (freq - 2407) / 5;

		return HOSTAPD_MODE_IEEE80211G;
	}

	if (freq == 2484) {
		if (sec_channel || chanwidth)
			return NUM_HOSTAPD_MODES;

		*op_class = 82; /* channel 14 */
		*channel = 14;

		return HOSTAPD_MODE_IEEE80211B;
	}

	if (freq >= 4900 && freq < 5000) {
		if ((freq - 4000) % 5)
			return NUM_HOSTAPD_MODES;
		*channel = (freq - 4000) / 5;
		*op_class = 0; /* TODO */
		return HOSTAPD_MODE_IEEE80211A;
	}

	switch (chanwidth) {
	case CHANWIDTH_80MHZ:
		vht_opclass = 128;
		break;
	case CHANWIDTH_160MHZ:
		vht_opclass = 129;
		break;
	case CHANWIDTH_80P80MHZ:
		vht_opclass = 130;
		break;
	default:
		vht_opclass = 0;
		break;
	}

	/* 5 GHz, channels 36..48 */
	if (freq >= 5180 && freq <= 5240) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 116;
		else if (sec_channel == -1)
			*op_class = 117;
		else
			*op_class = 115;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 5 GHz, channels 52..64 */
	if (freq >= 5260 && freq <= 5320) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 119;
		else if (sec_channel == -1)
			*op_class = 120;
		else
			*op_class = 118;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 5 GHz, channels 149..177 */
	if (freq >= 5745 && freq <= 5885) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 126;
		else if (sec_channel == -1)
			*op_class = 127;
		else if (freq <= 5805)
			*op_class = 124;
		else
			*op_class = 125;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 5 GHz, channels 100..144 */
	if (freq >= 5500 && freq <= 5720) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 122;
		else if (sec_channel == -1)
			*op_class = 123;
		else
			*op_class = 121;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 5000 && freq < 5900) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;
		*channel = (freq - 5000) / 5;
		*op_class = 0; /* TODO */
		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq > 5950 && freq <= 7115) {
		if ((freq - 5950) % 5)
			return NUM_HOSTAPD_MODES;

		switch (chanwidth) {
		case CHANWIDTH_80MHZ:
			*op_class = 133;
			break;
		case CHANWIDTH_160MHZ:
			*op_class = 134;
			break;
		case CHANWIDTH_80P80MHZ:
			*op_class = 135;
			break;
		default:
			if (sec_channel)
				*op_class = 132;
			else
				*op_class = 131;
			break;
		}

		*channel = (freq - 5950) / 5;
		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq == 5935) {
		*op_class = 136;
		*channel = (freq - 5925) / 5;
		return HOSTAPD_MODE_IEEE80211A;
	}

	/* 56.16 GHz, channel 1..6 */
	if (freq >= 56160 + 2160 * 1 && freq <= 56160 + 2160 * 6) {
		if (sec_channel)
			return NUM_HOSTAPD_MODES;

		switch (chanwidth) {
		case CHANWIDTH_USE_HT:
		case CHANWIDTH_2160MHZ:
			*channel = (freq - 56160) / 2160;
			*op_class = 180;
			break;
		case CHANWIDTH_4320MHZ:
			/* EDMG channels 9 - 13 */
			if (freq > 56160 + 2160 * 5)
				return NUM_HOSTAPD_MODES;

			*channel = (freq - 56160) / 2160 + 8;
			*op_class = 181;
			break;
		case CHANWIDTH_6480MHZ:
			/* EDMG channels 17 - 20 */
			if (freq > 56160 + 2160 * 4)
				return NUM_HOSTAPD_MODES;

			*channel = (freq - 56160) / 2160 + 16;
			*op_class = 182;
			break;
		case CHANWIDTH_8640MHZ:
			/* EDMG channels 25 - 27 */
			if (freq > 56160 + 2160 * 3)
				return NUM_HOSTAPD_MODES;

			*channel = (freq - 56160) / 2160 + 24;
			*op_class = 183;
			break;
		default:
			return NUM_HOSTAPD_MODES;
		}

		return HOSTAPD_MODE_IEEE80211AD;
	}

	return NUM_HOSTAPD_MODES;
}

/* --- platform.c:920-930 --- */
extern "C" {
UINT wifi_freq_to_op_class(UINT freq)
{
    u8 op_class, channel;

    if (ieee80211_freq_to_channel_ext(freq, 0, 0, &op_class, &channel) == NUM_HOSTAPD_MODES){
        wifi_hal_error_print("%s:%d Failed to get op class for freq : %d\n", __func__, __LINE__, freq);
        return RETURN_ERR;
    }

    return op_class;
}
}
