/*
 * HANDLER: wifi_dppCreateReconfigContext (src/wifi_hal_dpp.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fixes 1-3): src/wifi_hal_dpp.c:1680-1778 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fixes 1-3 applied (start fix n / end fix n markers, in the function and in the delete helper; the unfixed copy is the reproducer).  It frees an existing context, allocates a new
 * wifi_dpp_reconfig_instance_t, decodes the base64 net-access private key into keyasn1[1024], builds the EC key / public point / curve data, base64-encodes the public key into the caller's buffer and
 * sets the curve name (P-256 / P-384 / P-521); failure paths call delete_dpp_reconfig_context.
 *
 * Scaffolding only: OpenSSL is the real library; delete_dpp_reconfig_context is the real wifi_hal_dpp.c:1645-1678 copied verbatim (support code); malloc / free are counting wrappers; wifi_hal_dpp.c redirects
 * printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppCreateReconfigContext.
 */
#include "hwr_wrc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>

#define RETURN_OK 0
#define RETURN_ERR -1
hwr_wrc_world_t hwr_wrc_world;
extern "C" void *hwr_wrc_malloc(size_t n) { hwr_wrc_world.mallocs++; hwr_wrc_world.live++; return malloc(n); }
extern "C" void hwr_wrc_free(void *p) { if (p) hwr_wrc_world.live--; free(p); }
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define malloc hwr_wrc_malloc
#define free hwr_wrc_free
#define wifi_dppCreateReconfigContext hwr_sg_wifi_dppCreateReconfigContext

extern "C" {
/* --- wifi_hal_dpp.c:1645-1678 (verbatim, support code) --- */
int delete_dpp_reconfig_context(unsigned int ap_index, wifi_dpp_reconfig_instance_t *instance)
{
	if (instance == NULL) {
		printf("%s:%d:Invalid Argument\n", __func__, __LINE__);
		return RETURN_ERR;
	}
	if (instance->bnctx != NULL) {
		BN_CTX_free(instance->bnctx);
	}

	if (instance->key != NULL) {
		EC_KEY_free(instance->key);
	}

	if (instance->x != NULL) {
		BN_free(instance->x);
	}

	if (instance->y != NULL) {
		BN_free(instance->y);
	}

	if (instance->prime != NULL) {
		BN_free(instance->prime);
	}

	/* ---------- start fix 1: instance->pt is the key's own public point (EC_KEY_get0_public_key); EC_KEY_free above already released it, freeing it again was a double free. */
	/* ---------- end fix 1 */
	
	free(instance);

	return RETURN_OK;
}

/* --- wifi_hal_dpp.c:1680-1778 --- */
int wifi_dppCreateReconfigContext(unsigned int ap_index, char *net_access_key, wifi_dpp_reconfig_instance_t **inst, char *pub)
{
	wifi_dpp_reconfig_instance_t *instance;
    unsigned char keyasn1[1024];
    unsigned int pub_key_len;
    int asn1len;
    const unsigned char *key;
	EC_GROUP *group;
	unsigned char *pub_key;

    printf("%s:%d Here\n", __func__, __LINE__);

	if (inst == NULL) {
		printf("%s:%d:Invalid parameter\n", __func__, __LINE__);
		return RETURN_ERR;
	}
	/* ---------- start fix 3: net_access_key was passed to strlen and pub to EVP_EncodeBlock without a NULL check; a key longer than keyasn1 can hold after base64 decoding overflowed keyasn1. */
	if (net_access_key == NULL || pub == NULL || strlen(net_access_key) > (sizeof(keyasn1) / 3) * 4) {
		printf("%s:%d:Invalid parameter\n", __func__, __LINE__);
		return RETURN_ERR;
	}
	/* ---------- end fix 3 */
		
	instance = *inst;

	if (instance != NULL) {
		delete_dpp_reconfig_context(ap_index, instance);
	}

    printf("%s:%d Here\n", __func__, __LINE__);
	instance = (wifi_dpp_reconfig_instance_t *)malloc(sizeof(wifi_dpp_reconfig_instance_t));
	memset(instance, 0, sizeof(wifi_dpp_reconfig_instance_t));
	*inst = instance;

    printf("%s:%d Here\n", __func__, __LINE__);
    instance->bnctx = BN_CTX_new();

	// netaccess key

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)net_access_key, strlen(net_access_key))) < 0) { 
		delete_dpp_reconfig_context(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
        printf("%s:%d Failed to decode base 64 private access key\n", __func__, __LINE__);
        return RETURN_ERR;
    }    

    key = keyasn1;

    printf("%s:%d Here\n", __func__, __LINE__);

	if ((instance->key = d2i_ECPrivateKey(NULL,  &key, asn1len)) == NULL) {
		delete_dpp_reconfig_context(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
        printf("%s:%d Failed to create EC key\n", __func__, __LINE__);
        return RETURN_ERR;

	}

    printf("%s:%d Here\n", __func__, __LINE__);
    instance->pt = (EC_POINT*)EC_KEY_get0_public_key(instance->key);
    if (instance->pt == NULL) {
		delete_dpp_reconfig_context(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
        printf("%s:%d Could not get access public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

	pub_key_len = i2d_EC_PUBKEY(instance->key, &pub_key);
    printf("%s:%d Here public key length:%d\n", __func__, __LINE__, pub_key_len);
	EVP_EncodeBlock(pub, pub_key, pub_key_len);

    instance->x = BN_new();
    instance->y = BN_new();
	instance->prime = BN_new();

	group = (EC_GROUP*)EC_KEY_get0_group(instance->key);

	if (!EC_GROUP_get_curve_GFp(group, instance->prime, NULL, NULL, instance->bnctx)) {
		delete_dpp_reconfig_context(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(instance->key), instance->pt, instance->x, 
				instance->y, instance->bnctx)) {
		delete_dpp_reconfig_context(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

	switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(instance->key))) {
        case NID_X9_62_prime256v1:
			strcpy(instance->crv, "P-256");
            break;
        case NID_secp384r1:
			strcpy(instance->crv, "P-384");
            break;
        case NID_secp521r1:
			strcpy(instance->crv, "P-521");
            break;
        default:
        	/* ---------- start fix 2: an unsupported curve returned an error but left a half-built context in *inst. */
        	delete_dpp_reconfig_context(ap_index, instance);
        	*inst = NULL;
        	/* ---------- end fix 2 */
        	return RETURN_ERR;
    }

	return RETURN_OK;
	
}
}
