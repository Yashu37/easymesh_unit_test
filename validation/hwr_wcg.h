/* hwr_wcg.h - plumbing for the sg_wifi_dppCreateCSignIntance harness (src/wifi_hal_dpp.c).
 * OpenSSL (BN / EC / EVP / BIO / SHA) is the REAL library (libcrypto); wifi_dpp_csign_instance_t is declared exactly like wifi_hal_dpp.c:98-108.  The helpers the function uses - print_hex_dump
 * (:755-788), base64urlencode (:141-159), compute_key_hash (:970-1020), delete_dpp_csign_instance (:1780-1818) - are copied verbatim into the handler file as support code.  malloc / free used by the file are
 * counting wrappers (live instance blocks, including instance->bn); the printf of wifi_hal_dpp.c is redirected to a no-op sink exactly like the real file redirects it to wifi_dpp_dbg_print. */
#ifndef HWR_WCG_H
#define HWR_WCG_H
#include "hwr_defs.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
typedef struct {
	unsigned char kid[SHA512_DIGEST_LENGTH];
    BN_CTX *bnctx;
	BIGNUM *x, *y, *prime;
	EC_KEY	*key;
    EC_POINT *pt;
	EC_GROUP *group;
	char	alg[16];
	unsigned char 	*bn;
} wifi_dpp_csign_instance_t;
typedef struct { int live, mallocs; void *unrelated[4]; } hwr_wcg_world_t;
extern hwr_wcg_world_t hwr_wcg_world;
extern "C" void *hwr_wcg_malloc(size_t n);
extern "C" void hwr_wcg_free(void *p);
extern "C" int hwr_sg_wifi_dppCreateCSignIntance(unsigned int ap_index, char *c_sign_key, wifi_dpp_csign_instance_t **inst, unsigned char *sign_key_hash);
/* key ids: 0 P-256, 1 P-384, 2 P-521, 3 secp256k1 (unsupported curve), 4 invalid base64, 5 empty string, 6 truncated P-256, 7 valid base64 but no EC key, 8 1400 characters of valid base64 (decodes to 1050 bytes) */
typedef struct {
	const char *test_name;
	int calls;                     /* 1 or 2 consecutive calls on the same instance pointer */
	int key[2];
	int ap;
	int inst_null, key_null, hash_null;
	int pre_existing;              /* the instance pointer already holds a context made by the runner (bnctx only) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wcg_case_t;
extern hwr_wcg_case_t sg_wifi_dppCreateCSignIntance_suite[];
extern "C" void run_all_tests_sg_wifi_dppCreateCSignIntance(void);
#endif
