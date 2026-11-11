/* hwr_wrc.h - plumbing for the sg_wifi_dppCreateReconfigContext harness (src/wifi_hal_dpp.c).
 * OpenSSL (BN / EC / EVP) is the REAL library (libcrypto); wifi_dpp_reconfig_instance_t is declared exactly like wifi_hal_dpp.c:89-97.  delete_dpp_reconfig_context (wifi_hal_dpp.c:1645-1678, called by the
 * function on its failure paths and when an instance already exists) is copied verbatim into the handler file as support code.  malloc / free used by the file are counting wrappers (live instance blocks);
 * the printf of wifi_hal_dpp.c is redirected to a no-op sink exactly like the real file redirects it to wifi_dpp_dbg_print. */
#ifndef HWR_WRC_H
#define HWR_WRC_H
#include "hwr_defs.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
typedef struct {
    BN_CTX *bnctx;
	BIGNUM *x, *y, *prime;
	EC_KEY	*key;
    EC_POINT *pt;
	char	crv[16];
} wifi_dpp_reconfig_instance_t;
typedef struct { int live, mallocs; void *unrelated[4]; } hwr_wrc_world_t;
extern hwr_wrc_world_t hwr_wrc_world;
extern "C" void *hwr_wrc_malloc(size_t n);
extern "C" void hwr_wrc_free(void *p);
extern "C" int hwr_sg_wifi_dppCreateReconfigContext(unsigned int ap_index, char *net_access_key, wifi_dpp_reconfig_instance_t **inst, char *pub);
/* key ids: 0 P-256, 1 P-384, 2 P-521, 3 secp256k1 (unsupported curve), 4 invalid base64, 5 empty string, 6 truncated P-256, 7 valid base64 but no EC key, 8 1400 characters of valid base64 (decodes to 1050 bytes) */
typedef struct {
	const char *test_name;
	int calls;                     /* 1 or 2 consecutive calls on the same instance pointer */
	int key[2];
	int ap;
	int inst_null, key_null, pub_null;
	int pre_existing;              /* the instance pointer already holds a context made by the runner (bnctx only) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wrc_case_t;
extern hwr_wrc_case_t sg_wifi_dppCreateReconfigContext_suite[];
extern "C" void run_all_tests_sg_wifi_dppCreateReconfigContext(void);
#endif
