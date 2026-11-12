/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppProcessReconfigAnnouncement
 *
 * wifi_dppProcessReconfigAnnouncement(frame, len, key_hash): frame is a received DPP Reconfiguration Announcement (6-byte action frame body followed by attributes, len = the frame length), key_hash
 * is the caller's C-sign key hash (OneWifi: g_easy_connect.csign[ap].sign_key_hash, unsigned char[512] whose first 32 bytes hold the SHA-256 digest).  The runner builds REAL frames in heap blocks of
 * exactly the declared length and a 512-byte key_hash block.
 * Inputs crossed: frame / key_hash NULL, declared frame length (natural, 0, 3, 4, 5), 0..3 attributes in front of and 0..2 behind the C-sign hash attribute, the hash attribute absent / present with
 * the right hash / last byte flipped / first byte flipped / all zero / another attribute type carrying the same bytes / declared 4 bytes longer than present, attribute lengths 0, 1, 16, 31, 32, 33,
 * 100 and 600, an all-zero caller key hash.
 * Expected (CORRECT behaviour): RETURN_OK only for a frame whose C-sign key hash attribute is exactly 32 bytes long and equal to the caller's key hash; everything else (NULL pointers, short or
 * truncated frames, missing attribute, wrong length, mismatch) -> RETURN_ERR without reading outside the frame (the attributes start after the 6-byte body, so the scan length is len - 6) and without
 * reading the caller's key hash beyond the 32-byte digest; the frame and the key hash are not modified.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wrn.h"

/* name, nul, flen, before, after, tlv, hlen, zero_key, last */
hwr_wrn_case_t sg_wifi_dppProcessReconfigAnnouncement_suite[] = {
	{ "match_only_attribute",              0, -1, 0, 0, 1, 32, 0, 0 },
	{ "match_after_one_attribute",         0, -1, 1, 0, 1, 32, 0, 0 },
	{ "match_after_three_attributes",      0, -1, 3, 0, 1, 32, 0, 0 },
	{ "match_with_trailing_attributes",    0, -1, 0, 2, 1, 32, 0, 0 },
	{ "match_between_attributes",          0, -1, 2, 1, 1, 32, 0, 0 },
	{ "match_all_zero_key_hash",           0, -1, 0, 0, 1, 32, 1, 0 },
	{ "mismatch_last_byte",                0, -1, 0, 0, 2, 32, 0, 0 },
	{ "mismatch_first_byte",               0, -1, 0, 0, 3, 32, 0, 0 },
	{ "mismatch_all_zero_value",           0, -1, 0, 0, 4, 32, 0, 0 },
	{ "length_31",                         0, -1, 0, 0, 1, 31, 0, 0 },
	{ "length_16",                         0, -1, 0, 0, 1, 16, 0, 0 },
	{ "length_1",                          0, -1, 0, 0, 1, 1, 0, 0 },
	{ "length_0",                          0, -1, 0, 0, 1, 0, 0, 0 },
	{ "length_31_after_two_attributes",    0, -1, 2, 0, 1, 31, 0, 0 },
	{ "frame_length_0",                    0,  0, 0, 0, 0, 32, 0, 0 },
	{ "frame_length_3",                    0,  3, 0, 0, 0, 32, 0, 0 },
	/* inputs that crash the original: run LAST */
	{ "frame_null",                        1, -1, 0, 0, 1, 32, 0, 1 },
	{ "key_hash_null",                     2, -1, 0, 0, 1, 32, 0, 1 },
	{ "attribute_absent_header_only",      0, -1, 0, 0, 0, 32, 0, 1 },
	{ "frame_length_4",                    0,  4, 0, 0, 0, 32, 0, 1 },
	{ "frame_length_5",                    0,  5, 0, 0, 0, 32, 0, 1 },
	{ "attribute_absent_one_other",        0, -1, 1, 0, 0, 32, 0, 1 },
	{ "attribute_absent_three_others",     0, -1, 3, 0, 0, 32, 0, 1 },
	{ "other_type_with_hash_bytes",        0, -1, 0, 0, 5, 32, 0, 1 },
	{ "hash_attribute_truncated_by_4",     0, -1, 0, 0, 6, 32, 0, 1 },
	{ "length_33",                         0, -1, 0, 0, 1, 33, 0, 1 },
	{ "length_100",                        0, -1, 0, 0, 1, 100, 0, 1 },
	{ "length_600",                        0, -1, 0, 0, 1, 600, 0, 1 },
	{ NULL }
};
