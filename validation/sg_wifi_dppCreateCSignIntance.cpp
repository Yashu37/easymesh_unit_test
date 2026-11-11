/*
 * HANDLER: wifi_dppCreateCSignIntance (src/wifi_hal_dpp.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fixes 1-3): src/wifi_hal_dpp.c:1820-1966 (~/Desktop/G/rdk-wifi-hal), compiled for OpenSSL 1.1+.  This file holds the ORIGINAL code with fixes 1-3 applied (start fix n / end fix n markers, in the function and in the delete helper; the unfixed copy is the reproducer).  It frees an existing
 * C-sign context, allocates a new wifi_dpp_csign_instance_t, decodes the base64 C-sign private key into keyasn1[1024], builds the EC key / public point / curve data, the uncompressed public key bn
 * (0x04 || X || Y), its SHA-256 based key id (kid) and the caller's sign_key_hash (compute_key_hash) and sets the algorithm name (ES256 / ES384 / ES521); failure paths call delete_dpp_csign_instance.
 *
 * Scaffolding only: OpenSSL is the real library; print_hex_dump (:755-788), base64urlencode (:141-160), compute_key_hash (:970-1020) and delete_dpp_csign_instance (:1780-1818) are copied verbatim as
 * support code; malloc / free are counting wrappers; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppCreateCSignIntance.
 */
#include "hwr_wcg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>

#define RETURN_OK 0
#define RETURN_ERR -1
hwr_wcg_world_t hwr_wcg_world;
extern "C" void *hwr_wcg_malloc(size_t n) { hwr_wcg_world.mallocs++; hwr_wcg_world.live++; return malloc(n); }
extern "C" void hwr_wcg_free(void *p) { if (p) hwr_wcg_world.live--; free(p); }
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define malloc hwr_wcg_malloc
#define free hwr_wcg_free
#define wifi_dppCreateCSignIntance hwr_sg_wifi_dppCreateCSignIntance

extern "C" {
/* --- wifi_hal_dpp.c:755-788 (verbatim, support code) --- */
void print_hex_dump(unsigned int length, unsigned char *buffer)
{
    int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

/* --- wifi_hal_dpp.c:141-160 (verbatim, support code) --- */
int
base64urlencode (unsigned char *burl, unsigned char *data, int len)
{
    int octets, i;
    printf("%s:%d: HERE\n", __func__, __LINE__);
    octets = EVP_EncodeBlock(burl, data, len);
    for (i = 0; i < octets; i++) {
        if (burl[i] == '+') {
            burl[i] = '-';
        } else if (burl[i] == '/') {
            burl[i] = '_';
        }
    }
    while (burl[octets-1] == '=') {
        burl[octets-1] = '\0';
        octets--;
    }
    printf("%s:%d: HERE EXIT\n", __func__, __LINE__);
    return octets;
}

/* --- wifi_hal_dpp.c:970-1020 (verbatim, support code) --- */
static int
compute_key_hash (EC_KEY *key, unsigned char *digest)
{
    int asn1len;
    BIO *bio;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX ctx;
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
#endif
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        EVP_MD_CTX_free(ctx);
#endif
        return -1;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_init(&ctx);
#else
    EVP_MD_CTX_reset(ctx);
#endif
    (void)i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, asn1, asn1len);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, asn1, asn1len);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif

    BIO_free(bio);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_cleanup(&ctx);
#else
    EVP_MD_CTX_free(ctx);
#endif
    return mdlen;
}

/* --- wifi_hal_dpp.c:1780-1818 (verbatim, support code) --- */
int delete_dpp_csign_instance(unsigned int ap_index, wifi_dpp_csign_instance_t *instance)
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

	if (instance->bn != NULL) {
		free(instance->bn);
	}
	
	free(instance);
	
	return RETURN_OK;

}

/* --- wifi_hal_dpp.c:1820-1966 --- */
int wifi_dppCreateCSignIntance(unsigned int ap_index, char *c_sign_key, wifi_dpp_csign_instance_t **inst, unsigned char *sign_key_hash)
{
	wifi_dpp_csign_instance_t *instance;
	int bnlen, offset, b64len;
    unsigned char keyasn1[1024];
    int asn1len;
    const unsigned char *key;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX  ctx;
#else
    EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
#endif
	unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
	unsigned char *ptr;

    printf("%s:%d Here\n", __func__, __LINE__);

	if (inst == NULL) {
		printf("%s:%d:Invalid parameter\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
		EVP_MD_CTX_free(ctx);
#endif
		return RETURN_ERR;
	}
	/* ---------- start fix 3: c_sign_key was passed to strlen and sign_key_hash to compute_key_hash (memset) without a NULL check; a key longer than keyasn1 can hold after base64 decoding overflowed keyasn1. */
	if (c_sign_key == NULL || sign_key_hash == NULL || strlen(c_sign_key) > (sizeof(keyasn1) / 3) * 4) {
		printf("%s:%d:Invalid parameter\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
		EVP_MD_CTX_free(ctx);
#endif
		return RETURN_ERR;
	}
	/* ---------- end fix 3 */

	instance = *inst;
	
	if (instance != NULL) {
		delete_dpp_csign_instance(ap_index, instance);
	}

	instance = (wifi_dpp_csign_instance_t *)malloc(sizeof(wifi_dpp_csign_instance_t));
	memset(instance, 0, sizeof(wifi_dpp_csign_instance_t));
	*inst = instance;

    instance->bnctx = BN_CTX_new();

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)c_sign_key, strlen(c_sign_key))) < 0) { 
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
        printf("%s:%d Failed to decode base 64 private access key\n", __func__, __LINE__);
        return RETURN_ERR;
    }    

    key = keyasn1;

    printf("%s:%d Here\n", __func__, __LINE__);

	if ((instance->key = d2i_ECPrivateKey(NULL,  &key, asn1len)) == NULL) {
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
        printf("%s:%d Failed to create EC key\n", __func__, __LINE__);
        return RETURN_ERR;

	}

    printf("%s:%d Here\n", __func__, __LINE__);
    instance->pt = (EC_POINT*)EC_KEY_get0_public_key(instance->key);
    if (instance->pt == NULL) {
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
        printf("%s:%d Could not get access public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    instance->x = BN_new();
    instance->y = BN_new();
	instance->prime = BN_new();

	instance->group = (EC_GROUP*)EC_KEY_get0_group(instance->key);

	if (!EC_GROUP_get_curve_GFp(instance->group, instance->prime, NULL, NULL, instance->bnctx)) {
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(instance->key), instance->pt, instance->x, 
				instance->y, instance->bnctx)) {
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

	switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(instance->key))) {
        case NID_X9_62_prime256v1:
			strcpy(instance->alg, "ES256");
			bnlen = 32;
            break;
        case NID_secp384r1:
			strcpy(instance->alg, "ES384");
			bnlen = 48;
            break;
        case NID_secp521r1:
			strcpy(instance->alg, "ES521");
			bnlen = 66;
            break;
        default:
        	/* ---------- start fix 2: an unsupported curve returned an error but left a half-built context in *inst. */
        	delete_dpp_csign_instance(ap_index, instance);
        	*inst = NULL;
        	/* ---------- end fix 2 */
        	return RETURN_ERR;
    }
    if ((instance->bn = (unsigned char *)malloc(2*bnlen + 1)) == NULL) {
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(instance->bn, 0, (2*bnlen + 1));
    instance->bn[0] = 0x04;
    ptr = &instance->bn[1];
    offset = bnlen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, ptr + offset);
    ptr = &instance->bn[1+bnlen];
    offset = bnlen - BN_num_bytes(instance->y);
    BN_bn2bin(instance->y, ptr + offset);

	printf("%s:%d: csign public key\n", __func__, __LINE__);
	print_hex_dump(2*bnlen + 1, instance->bn);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, instance->bn, 2*bnlen + 1);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else	
	EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, instance->bn, 2*bnlen + 1);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif
	
	compute_key_hash(instance->key, sign_key_hash);
	
	printf("%s:%d: csign public key hash\n", __func__, __LINE__);
	print_hex_dump(SHA256_DIGEST_LENGTH, sign_key_hash);
    
	if ((b64len = base64urlencode(instance->kid, digest, mdlen)) < 0) {
		delete_dpp_csign_instance(ap_index, instance);
		/* ---------- start fix 2: *inst was left pointing at the freed context. */
		*inst = NULL;
		/* ---------- end fix 2 */
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    instance->kid[b64len] = '\0';
		

	printf("%s:%d kid:%s alg:%s\n", __func__, __LINE__, instance->kid, instance->alg);

	return RETURN_OK;
	
}
}
