/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2019 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <jni.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"
#include "NativeCrypto_md.h"


//Header for RSA algorithm using 1.0.2 OpenSSL
int OSSL102_RSA_set0_key(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
int OSSL102_RSA_set0_factors(RSA *, BIGNUM *, BIGNUM *);
int OSSL102_RSA_set0_crt_params(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);

//Type definitions for function pointers
typedef char * OSSL_error_string_t(unsigned long, char *);
typedef char * OSSL_error_string_n_t(unsigned long, char *, size_t);
typedef unsigned long OSSL_get_error_t();
typedef const EVP_MD* OSSL_sha_t();
typedef EVP_MD_CTX* OSSL_MD_CTX_new_t();
typedef int OSSL_DigestInit_ex_t(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
typedef int OSSL_MD_CTX_copy_ex_t(EVP_MD_CTX *, const EVP_MD_CTX *);
typedef int OSSL_DigestUpdate_t(EVP_MD_CTX *, const void *, size_t);
typedef int OSSL_DigestFinal_ex_t(EVP_MD_CTX *, unsigned char *, unsigned int *);
typedef int OSSL_MD_CTX_reset_t(EVP_MD_CTX *);
typedef int OSSL_MD_CTX_free_t(EVP_MD_CTX *);
typedef EVP_CIPHER_CTX* OSSL_CIPHER_CTX_new_t();
typedef void OSSL_CIPHER_CTX_free_t(EVP_CIPHER_CTX *);
typedef const EVP_CIPHER* OSSL_aes_t();
typedef int OSSL_CipherInit_ex_t(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                              ENGINE *, const unsigned char *, const unsigned char *, int);
typedef int OSSL_CIPHER_CTX_set_padding_t(EVP_CIPHER_CTX *, int);
typedef int OSSL_CipherUpdate_t(EVP_CIPHER_CTX *, unsigned char *, int *,
                              const unsigned char *, int);
typedef int OSSL_CipherFinal_ex_t(EVP_CIPHER_CTX *, unsigned char *, int *);
typedef int OSSL_CIPHER_CTX_ctrl_t(EVP_CIPHER_CTX *, int, int, void *);
typedef int OSSL_DecryptInit_ex_t(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                             ENGINE *, const unsigned char *, const unsigned char *);
typedef int OSSL_DecryptUpdate_t(EVP_CIPHER_CTX *, unsigned char *, int *,
                             const unsigned char *, int);
typedef int OSSL_DecryptFinal_t(EVP_CIPHER_CTX *, unsigned char *, int *);

typedef RSA* OSSL_RSA_new_t();
typedef int OSSL_RSA_set0_key_t(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
typedef int OSSL_RSA_set0_factors_t(RSA *, BIGNUM *, BIGNUM *);
typedef void OSSL_RSA_free_t (RSA *);
typedef int OSSL_RSA_public_decrypt_t(int, const unsigned char *, unsigned char *, RSA *, int);
typedef int OSSL_RSA_private_encrypt_t (int, const unsigned char *, unsigned char *, RSA *, int);
typedef BIGNUM* OSSL_BN_bin2bn_t (const unsigned char *, int, BIGNUM *);
typedef void OSSL_BN_set_negative_t (BIGNUM *, int);
typedef void OSSL_BN_free_t (BIGNUM *);

//Define pointers for OpenSSL functions to handle Errors.
OSSL_error_string_t* OSSL_error_string;
OSSL_error_string_n_t* OSSL_error_string_n;
OSSL_get_error_t* OSSL_get_error;

//Define pointers for OpenSSL functions to handle Message Digest algorithms.
OSSL_sha_t* OSSL_sha1;
OSSL_sha_t* OSSL_sha256;
OSSL_sha_t* OSSL_sha224;
OSSL_sha_t* OSSL_sha384;
OSSL_sha_t* OSSL_sha512;
OSSL_MD_CTX_new_t* OSSL_MD_CTX_new;
OSSL_DigestInit_ex_t* OSSL_DigestInit_ex;
OSSL_MD_CTX_copy_ex_t* OSSL_MD_CTX_copy_ex;
OSSL_DigestUpdate_t* OSSL_DigestUpdate;
OSSL_DigestFinal_ex_t* OSSL_DigestFinal_ex;
OSSL_MD_CTX_reset_t* OSSL_MD_CTX_reset;
OSSL_MD_CTX_free_t* OSSL_MD_CTX_free;

//Define pointers for OpenSSL functions to handle CBC and GCM Cipher algorithms.
OSSL_CIPHER_CTX_new_t* OSSL_CIPHER_CTX_new;
OSSL_CIPHER_CTX_free_t* OSSL_CIPHER_CTX_free;
OSSL_aes_t* OSSL_aes_128_cbc;
OSSL_aes_t* OSSL_aes_192_cbc;
OSSL_aes_t* OSSL_aes_256_cbc;
OSSL_CipherInit_ex_t* OSSL_CipherInit_ex;
OSSL_CIPHER_CTX_set_padding_t* OSSL_CIPHER_CTX_set_padding;
OSSL_CipherUpdate_t* OSSL_CipherUpdate;
OSSL_CipherFinal_ex_t* OSSL_CipherFinal_ex;

//Define pointers for OpenSSL functions to handle GCM algorithm.
OSSL_aes_t* OSSL_aes_128_gcm;
OSSL_aes_t* OSSL_aes_192_gcm;
OSSL_aes_t* OSSL_aes_256_gcm;
OSSL_CIPHER_CTX_ctrl_t* OSSL_CIPHER_CTX_ctrl;
OSSL_DecryptInit_ex_t* OSSL_DecryptInit_ex;
OSSL_DecryptUpdate_t* OSSL_DecryptUpdate;
OSSL_DecryptFinal_t* OSSL_DecryptFinal;

//Define pointers for OpenSSL functions to handle RSA algorithm.
OSSL_RSA_new_t* OSSL_RSA_new;
OSSL_RSA_set0_key_t* OSSL_RSA_set0_key;
OSSL_RSA_set0_factors_t* OSSL_RSA_set0_factors;
OSSL_RSA_set0_key_t* OSSL_RSA_set0_crt_params;
OSSL_RSA_free_t* OSSL_RSA_free;
OSSL_RSA_public_decrypt_t* OSSL_RSA_public_decrypt;
OSSL_RSA_private_encrypt_t* OSSL_RSA_private_encrypt;
OSSL_BN_bin2bn_t* OSSL_BN_bin2bn;
OSSL_BN_set_negative_t* OSSL_BN_set_negative;
OSSL_BN_free_t* OSSL_BN_free;

/* Structure for OpenSSL Digest context */
typedef struct OpenSSLMDContext {
    EVP_MD_CTX *ctx;
    const EVP_MD *digestAlg;
} OpenSSLMDContext;

/* Handle errors from OpenSSL calls */
static void printErrors(void) {
    unsigned long errCode = 0;

    fprintf(stderr, "An OpenSSL error occurred\n");
    while(0 != (errCode = (*OSSL_get_error)()))
    {
        char err_str[120];
        (*OSSL_error_string_n)(errCode, err_str, (sizeof(err_str) / sizeof(char)));
        fprintf(stderr, "%s\n", err_str);
    }
    fflush(stderr);
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    loadCrypto
 * Signature: ()V
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_loadCrypto
  (JNIEnv *env, jclass thisObj){

    void *handle = NULL;
    typedef const char* OSSL_version_t(int);

     // Determine the version of OpenSSL.
    OSSL_version_t* OSSL_version;
    const char * openssl_version;
    int ossl_ver;

    // Load OpenSSL Crypto library
    handle = load_crypto_library();
    if (NULL == handle) {
        //fprintf(stderr, " :FAILED TO LOAD OPENSSL CRYPTO LIBRARY\n");
        //fflush(stderr);
        return -1;
    }

    // Different symbols are used by OpenSSL with 1.0 and 1.1.
    // The symbol 'OpenSSL_version' is used by OpenSSL 1.1 where as
    // the symbol "SSLeay_version" is used by OpenSSL 1.0.
    // Currently only openssl 1.0.2 and 1.1.0 and 1.1.1 are supported.
    OSSL_version = (OSSL_version_t*)find_crypto_symbol(handle, "OpenSSL_version");

    if (NULL == OSSL_version)  {
        OSSL_version = (OSSL_version_t*)find_crypto_symbol(handle, "SSLeay_version");

        if (NULL == OSSL_version)  {
            //fprintf(stderr, "Only openssl 1.0.2 and 1.1.0 and 1.1.1 are supported\n");
            //fflush(stderr);
            unload_crypto_library(handle);
            return -1;
        } else {
            openssl_version = (*OSSL_version)(0); //get OPENSSL_VERSION
            //Ensure the OpenSSL version is "OpenSSL 1.0.2"
            if (0 != strncmp(openssl_version, "OpenSSL 1.0.2", 13)) {
                //fprintf(stderr, "Incompatable OpenSSL version: %s\n", openssl_version);
                //fflush(stderr);
                unload_crypto_library(handle);
                return -1;
            }
            ossl_ver = 0;
        }
    } else {
        openssl_version = (*OSSL_version)(0); //get OPENSSL_VERSION
        //Ensure the OpenSSL version is "OpenSSL 1.1.0" or "OpenSSL 1.1.0".
        if (0 != strncmp(openssl_version, "OpenSSL 1.1.0", 13) &&
            0 != strncmp(openssl_version, "OpenSSL 1.1.1", 13)) {
            //fprintf(stderr, "Incompatable OpenSSL version: %s\n", openssl_version);
            //fflush(stderr);
            unload_crypto_library(handle);
            return -1;
        }
        ossl_ver = 1;
    }

    // Load the function symbols for OpenSSL errors.
    OSSL_error_string = (OSSL_error_string_t*)find_crypto_symbol(handle, "ERR_error_string");
    OSSL_get_error = (OSSL_get_error_t*)find_crypto_symbol(handle, "ERR_get_error");

    //Load the function symbols for OpenSSL Message Digest algorithms.
    OSSL_sha1 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha1");
    OSSL_sha256 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha256");
    OSSL_sha224 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha224");
    OSSL_sha384 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha384");
    OSSL_sha512 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha512");

    if (1 == ossl_ver) {
        OSSL_MD_CTX_new = (OSSL_MD_CTX_new_t*)find_crypto_symbol(handle, "EVP_MD_CTX_new");
        OSSL_MD_CTX_reset = (OSSL_MD_CTX_reset_t*)find_crypto_symbol(handle, "EVP_MD_CTX_reset");
        OSSL_MD_CTX_free = (OSSL_MD_CTX_free_t*)find_crypto_symbol(handle, "EVP_MD_CTX_free");
    } else {
        OSSL_MD_CTX_new = (OSSL_MD_CTX_new_t*)find_crypto_symbol(handle, "EVP_MD_CTX_create");
        OSSL_MD_CTX_reset = (OSSL_MD_CTX_reset_t*)find_crypto_symbol(handle, "EVP_MD_CTX_cleanup");
        OSSL_MD_CTX_free = (OSSL_MD_CTX_free_t*)find_crypto_symbol(handle, "EVP_MD_CTX_destroy");
    }

    OSSL_DigestInit_ex = (OSSL_DigestInit_ex_t*)find_crypto_symbol(handle, "EVP_DigestInit_ex");
    OSSL_MD_CTX_copy_ex = (OSSL_MD_CTX_copy_ex_t*)find_crypto_symbol(handle, "EVP_MD_CTX_copy_ex");
    OSSL_DigestUpdate = (OSSL_DigestUpdate_t*)find_crypto_symbol(handle, "EVP_DigestUpdate");
    OSSL_DigestFinal_ex = (OSSL_DigestFinal_ex_t*)find_crypto_symbol(handle, "EVP_DigestFinal_ex");

    //Load the function symbols for OpenSSL CBC and GCM Cipher algorithms.
    OSSL_CIPHER_CTX_new = (OSSL_CIPHER_CTX_new_t*)find_crypto_symbol(handle, "EVP_CIPHER_CTX_new");
    OSSL_CIPHER_CTX_free = (OSSL_CIPHER_CTX_free_t*)find_crypto_symbol(handle, "EVP_CIPHER_CTX_free");
    OSSL_aes_128_cbc = (OSSL_aes_t*)find_crypto_symbol(handle, "EVP_aes_128_cbc");
    OSSL_aes_192_cbc = (OSSL_aes_t*)find_crypto_symbol(handle, "EVP_aes_192_cbc");
    OSSL_aes_256_cbc = (OSSL_aes_t*)find_crypto_symbol(handle, "EVP_aes_256_cbc");
    OSSL_CipherInit_ex = (OSSL_CipherInit_ex_t*)find_crypto_symbol(handle, "EVP_CipherInit_ex");
    OSSL_CIPHER_CTX_set_padding = (OSSL_CIPHER_CTX_set_padding_t*)find_crypto_symbol(handle, "EVP_CIPHER_CTX_set_padding");
    OSSL_CipherUpdate = (OSSL_CipherUpdate_t*)find_crypto_symbol(handle, "EVP_CipherUpdate");
    OSSL_CipherFinal_ex = (OSSL_CipherFinal_ex_t*)find_crypto_symbol(handle, "EVP_CipherFinal_ex");
    OSSL_aes_128_gcm = (OSSL_aes_t*)find_crypto_symbol(handle, "EVP_aes_128_gcm");
    OSSL_aes_192_gcm = (OSSL_aes_t*)find_crypto_symbol(handle, "EVP_aes_192_gcm");
    OSSL_aes_256_gcm = (OSSL_aes_t*)find_crypto_symbol(handle, "EVP_aes_256_gcm");
    OSSL_CIPHER_CTX_ctrl = (OSSL_CIPHER_CTX_ctrl_t*)find_crypto_symbol(handle, "EVP_CIPHER_CTX_ctrl");
    OSSL_DecryptInit_ex = (OSSL_DecryptInit_ex_t*)find_crypto_symbol(handle, "EVP_DecryptInit_ex");
    OSSL_DecryptUpdate = (OSSL_DecryptUpdate_t*)find_crypto_symbol(handle, "EVP_DecryptUpdate");
    OSSL_DecryptFinal = (OSSL_DecryptFinal_t*)find_crypto_symbol(handle, "EVP_DecryptFinal");

    //Load the functions symbols for Openssl RSA algorithm.
    OSSL_RSA_new = (OSSL_RSA_new_t*)find_crypto_symbol(handle, "RSA_new");

    if (1 == ossl_ver) {
        OSSL_RSA_set0_key = (OSSL_RSA_set0_key_t*)find_crypto_symbol(handle, "RSA_set0_key");
        OSSL_RSA_set0_factors = (OSSL_RSA_set0_factors_t*)find_crypto_symbol(handle, "RSA_set0_factors");
        OSSL_RSA_set0_crt_params = (OSSL_RSA_set0_key_t*)find_crypto_symbol(handle, "RSA_set0_crt_params");
    } else {
        OSSL_RSA_set0_key = &OSSL102_RSA_set0_key;
        OSSL_RSA_set0_factors = &OSSL102_RSA_set0_factors;
        OSSL_RSA_set0_crt_params = &OSSL102_RSA_set0_crt_params;
    }
    OSSL_RSA_free = (OSSL_RSA_free_t *)find_crypto_symbol(handle, "RSA_free");
    OSSL_RSA_public_decrypt = (OSSL_RSA_public_decrypt_t *)find_crypto_symbol(handle, "RSA_public_decrypt");
    OSSL_RSA_private_encrypt = (OSSL_RSA_private_encrypt_t *)find_crypto_symbol(handle, "RSA_private_decrypt");
    OSSL_BN_bin2bn = (OSSL_BN_bin2bn_t *)find_crypto_symbol(handle, "BN_bin2bn");
    OSSL_BN_set_negative = (OSSL_BN_set_negative_t *)find_crypto_symbol(handle, "BN_set_negative");
    OSSL_BN_free = (OSSL_BN_free_t *)find_crypto_symbol(handle, "BN_free");

    if ((NULL == OSSL_error_string) ||
        (NULL == OSSL_get_error) ||
        (NULL == OSSL_sha1) ||
        (NULL == OSSL_sha256) ||
        (NULL == OSSL_sha224) ||
        (NULL == OSSL_sha384) ||
        (NULL == OSSL_sha512) ||
        (NULL == OSSL_MD_CTX_new) ||
        (NULL == OSSL_MD_CTX_reset) ||
        (NULL == OSSL_MD_CTX_free) ||
        (NULL == OSSL_DigestInit_ex) ||
        (NULL == OSSL_MD_CTX_copy_ex) ||
        (NULL == OSSL_DigestUpdate) ||
        (NULL == OSSL_DigestFinal_ex) ||
        (NULL == OSSL_CIPHER_CTX_new) ||
        (NULL == OSSL_CIPHER_CTX_free) ||
        (NULL == OSSL_aes_128_cbc) ||
        (NULL == OSSL_aes_192_cbc) ||
        (NULL == OSSL_aes_256_cbc) ||
        (NULL == OSSL_CipherInit_ex) ||
        (NULL == OSSL_CIPHER_CTX_set_padding) ||
        (NULL == OSSL_CipherUpdate) ||
        (NULL == OSSL_CipherFinal_ex) ||
        (NULL == OSSL_aes_128_gcm) ||
        (NULL == OSSL_aes_192_gcm) ||
        (NULL == OSSL_aes_256_gcm) ||
        (NULL == OSSL_CIPHER_CTX_ctrl) ||
        (NULL == OSSL_DecryptInit_ex) ||
        (NULL == OSSL_DecryptUpdate) ||
        (NULL == OSSL_DecryptFinal) ||
        (NULL == OSSL_RSA_new) ||
        (NULL == OSSL_RSA_set0_key) ||
        (NULL == OSSL_RSA_set0_factors) ||
        (NULL == OSSL_RSA_set0_crt_params) ||
        (NULL == OSSL_RSA_free) ||
        (NULL == OSSL_RSA_public_decrypt) ||
        (NULL == OSSL_RSA_private_encrypt) ||
        (NULL == OSSL_BN_bin2bn) ||
        (NULL == OSSL_BN_set_negative) ||
        (NULL == OSSL_BN_free)) {
        //fprintf(stderr, "One or more of the required symbols are missing in the crypto library\n");
        //fflush(stderr);
        unload_crypto_library(handle);
        return -1;
    } else {
        return 0;
    }
 }

/* Create Digest context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestCreateContext
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestCreateContext
  (JNIEnv *env, jclass thisObj, jlong copyContext, jint algoIdx) {

    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *digestAlg = NULL;
    OpenSSLMDContext *context = NULL;

    switch (algoIdx) {
        case 0:
            digestAlg = (*OSSL_sha1)();
            break;
        case 1:
            digestAlg = (*OSSL_sha256)();
            break;
        case 2:
            digestAlg = (*OSSL_sha224)();
            break;
        case 3:
            digestAlg = (*OSSL_sha384)();
            break;
        case 4:
            digestAlg = (*OSSL_sha512)();
            break;
        default:
            return -1;
    }

    if (NULL == (ctx = (*OSSL_MD_CTX_new)())) {
        printErrors();
        return -1;
    }

    if (1 != (*OSSL_DigestInit_ex)(ctx, digestAlg, NULL)) {
        printErrors();
        (*OSSL_MD_CTX_free)(ctx);
        return -1;
    }

    context = malloc(sizeof(OpenSSLMDContext));
    if (NULL == context) {
        (*OSSL_MD_CTX_free)(ctx);
        return -1;
    }

    context->ctx = ctx;
    context->digestAlg = digestAlg;

    if (0 != copyContext) {
        EVP_MD_CTX *contextToCopy = ((OpenSSLMDContext*)(intptr_t)copyContext)->ctx;
        if (NULL == contextToCopy) {
            (*OSSL_MD_CTX_free)(ctx);
            free(context);
            return -1;
        }
        if (0 == (*OSSL_MD_CTX_copy_ex)(ctx, contextToCopy)) {
            printErrors();
            (*OSSL_MD_CTX_free)(ctx);
            free(context);
            return -1;
        }

    }

    return (jlong)(intptr_t)context;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestDestroyContext
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestDestroyContext
  (JNIEnv *env, jclass thisObj, jlong c) {

    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;
    if ((NULL == context) || (NULL == context->ctx)) {
        return -1;
    }

    (*OSSL_MD_CTX_free)(context->ctx);
    free(context);
    return 0;
}

/* Update Digest context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestUpdate
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestUpdate
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray message, jint messageOffset,
  jint messageLen) {

    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;
    unsigned char* messageNative = NULL;

    if (NULL == context) {
        return -1;
    }
    if (NULL == message) {
        return -1;
    }

    messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
    if (NULL == messageNative) {
        return -1;
    }

    if (1 != (*OSSL_DigestUpdate)(context->ctx, (messageNative + messageOffset), messageLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);

    return 0;
}

/* Compute and Reset Digest
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestComputeAndReset
 * Signature: (J[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestComputeAndReset
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray message, jint messageOffset, jint messageLen,
  jbyteArray digest, jint digestOffset, jint digestLen) {

    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;

    unsigned int size = 0;
    unsigned char* messageNative = NULL;
    unsigned char* digestNative = NULL;

    if ((NULL == context) || (NULL == context->ctx)) {
        return -1;
    }

    if (NULL != message) {
        messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
        if (NULL == messageNative) {
            return -1;
        }

        if (1 != (*OSSL_DigestUpdate)(context->ctx, (messageNative + messageOffset), messageLen)) {
            printErrors();
            (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);
            return -1;
        }

        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);
    }

    digestNative = (*env)->GetPrimitiveArrayCritical(env, digest, 0);
    if (NULL == digestNative) {
        return -1;
    }

    if (1 != (*OSSL_DigestFinal_ex)(context->ctx, (digestNative + digestOffset), &size)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, 0);

    (*OSSL_MD_CTX_reset)(context->ctx);

    if (1 != (*OSSL_DigestInit_ex)(context->ctx, context->digestAlg, NULL)) {
        printErrors();
        return -1;
    }

    return (jint)size;
}

/* Reset Digest
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestReset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestReset
  (JNIEnv *env, jclass thisObj, jlong c) {

    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;

    if ((NULL == context) || (NULL == context->ctx)) {
        return;
    }

    (*OSSL_MD_CTX_reset)(context->ctx);

    if (1 != (*OSSL_DigestInit_ex)(context->ctx, context->digestAlg, NULL)) {
        printErrors();
    }
}

/* Create Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCCreateContext
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCCreateContext
  (JNIEnv *env, jclass thisObj) {

    EVP_CIPHER_CTX *ctx = NULL;

    /* Create and initialise the context */
    if (NULL == (ctx = (*OSSL_CIPHER_CTX_new)())) {
        printErrors();
        return -1;
    }

    return (jlong)(intptr_t)ctx;
}

/* Destroy Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCDestroyContext
 * Signature: (J)J
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCDestroyContext
  (JNIEnv *env, jclass thisObj, jlong c) {

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;
    if (NULL == ctx) {
        return -1;
    }

    (*OSSL_CIPHER_CTX_free)(ctx);
    return 0;
}

/* Initialize CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCInit
 * Signature: (JI[BI[BI)V
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCInit
  (JNIEnv *env, jclass thisObj, jlong c, jint mode, jbyteArray iv, jint iv_len,
  jbyteArray key, jint key_len) {

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;
    unsigned char* ivNative = NULL;
    unsigned char* keyNative = NULL;
    const EVP_CIPHER * evp_cipher1 = NULL;

    if (NULL == ctx) {
        return -1;
    }

    switch(key_len) {
        case 16:
            evp_cipher1 = (*OSSL_aes_128_cbc)();
            break;
        case 24:
            evp_cipher1 = (*OSSL_aes_192_cbc)();
            break;
        case 32:
            evp_cipher1 = (*OSSL_aes_256_cbc)();
            break;
        default:
            break;
    }

    ivNative = (unsigned char*)((*env)->GetByteArrayElements(env, iv, 0));
    if (NULL == ivNative) {
        return -1;
    }

    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, 0));
    if (NULL == keyNative) {
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_cipher1, NULL, keyNative, ivNative, mode)) {
        printErrors();
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
        return -1;
    }

    (*OSSL_CIPHER_CTX_set_padding)(ctx, 0);

    (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
    return 0;
}

/* Update CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCUpdate
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCUpdate
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset) {

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    int outputLen = 0;

    unsigned char* inputNative;
    unsigned char* outputNative;

    if (NULL == ctx) {
        return -1;
    }

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (NULL == inputNative) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return (jint)outputLen;
}

/* CBC Final Encryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCFinalEncrypt
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCFinalEncrypt
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset) {

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    unsigned char buf[16];

    int outputLen = -1;
    int outputLen1 = -1;

    unsigned char* inputNative = NULL;
    unsigned char* outputNative = NULL;

    if (NULL == ctx) {
        return -1;
    }

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (NULL == inputNative) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherFinal_ex)(ctx, buf, &outputLen1)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return (jint)(outputLen + outputLen1);
}

int first_time_gcm = 0;

/* GCM Encryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    GCMEncrypt
 * Signature: ([BI[BI[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_GCMEncrypt
  (JNIEnv * env, jclass obj, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
  jbyteArray input, jint inOffset, jint inLen, jbyteArray output, jint outOffset,
  jbyteArray aad, jint aadLen, jint tagLen) {

    unsigned char* inputNative = NULL;
    int len = 0, len_cipher = 0;
    unsigned char* keyNative = NULL;
    unsigned char* ivNative = NULL;
    unsigned char* outputNative = NULL;
    unsigned char* aadNative = NULL;

    EVP_CIPHER_CTX* ctx = NULL;
    const EVP_CIPHER* evp_gcm_cipher = NULL;

    keyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (NULL == keyNative) {
        return -1;
    }

    ivNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv, 0));
    if (NULL == ivNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        return -1;
    }

    aadNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
    if (NULL == aadNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        return -1;
    }

    if (inLen > 0) {
        inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (NULL == inputNative) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            return -1;
        }
    }

    switch(keyLen) {
        case 16:
            evp_gcm_cipher = (*OSSL_aes_128_gcm)();
            break;
        case 24:
            evp_gcm_cipher = (*OSSL_aes_192_gcm)();
            break;
        case 32:
            evp_gcm_cipher = (*OSSL_aes_256_gcm)();
            break;
        default:
            break;
    }

    ctx = (*OSSL_CIPHER_CTX_new)();
    if (NULL == ctx) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_gcm_cipher, NULL, NULL, NULL, 1 )) { /* 1 - Encrypt mode 0 Decrypt Mode*/
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, NULL, NULL, keyNative, ivNative, -1)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    /* provide AAD */
    if (1 != (*OSSL_CipherUpdate)(ctx, NULL, &len, aadNative, aadLen)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    /* encrypt plaintext and obtain ciphertext */
    if (inLen > 0) {
        if (1 != (*OSSL_CipherUpdate)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen)) {
            printErrors();
            (*OSSL_CIPHER_CTX_free)(ctx);
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            if (inLen > 0) {
                (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            }
            return -1;
        }
        len_cipher = len;
    }

    /* finalize the encryption */
    if (1 != (*OSSL_CipherFinal_ex)(ctx, outputNative + outOffset + len_cipher, &len)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    /* Get the tag, place it at the end of the cipherText buffer */
    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, outputNative + outOffset + len + len_cipher)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }


    (*OSSL_CIPHER_CTX_free)(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);

    return (jint)len_cipher;
}

/* GCM Decryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    GCMDecrypt
 * Signature: ([BI[BI[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_GCMDecrypt
  (JNIEnv * env, jclass obj, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
  jbyteArray input, jint inOffset, jint inLen, jbyteArray output, jint outOffset,
  jbyteArray aad, jint aadLen, jint tagLen) {

    unsigned char* inputNative = NULL;
    unsigned char* aadNative = NULL;
    int ret = 0, len = 0, plaintext_len = 0;
    unsigned char* keyNative = NULL;
    unsigned char* ivNative = NULL;
    unsigned char* outputNative = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    const EVP_CIPHER* evp_gcm_cipher = NULL;

    keyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (NULL == keyNative)
        return -1;

    ivNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv, 0));
    if (NULL == ivNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        return -1;
    }

    if (inLen > 0) {
        inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (NULL == inputNative) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            return -1;
        }
    }

    if (aadLen > 0) {
        aadNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
        if (NULL == aadNative) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            if (inLen > 0)
                (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            return -1;
        }
    }

    switch(keyLen) {
        case 16:
            evp_gcm_cipher = (*OSSL_aes_128_gcm)();
            break;
        case 24:
            evp_gcm_cipher = (*OSSL_aes_192_gcm)();
            break;
        case 32:
            evp_gcm_cipher = (*OSSL_aes_256_gcm)();
            break;
        default:
            break;
    }

    ctx = (*OSSL_CIPHER_CTX_new)();

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_gcm_cipher, NULL, NULL, NULL, 0 )) { /* 1 - Encrypt mode 0 Decrypt Mode*/
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        if (aadLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        }
        return -1;
    }

    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        if (aadLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        }
        return -1;
    }

    /* Initialise key and IV */
    if (0 == (*OSSL_DecryptInit_ex)(ctx, NULL, NULL, keyNative, ivNative)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        if (aadLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        }
        return -1;
    }

    /* Provide any AAD data */
    if (aadLen > 0) {
        if (0 == (*OSSL_DecryptUpdate)(ctx, NULL, &len, aadNative, aadLen)) {
            printErrors();
            (*OSSL_CIPHER_CTX_free)(ctx);
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            if (inLen > 0) {
                (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            }
            if (aadLen > 0) {
                (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
            }
            return -1;
        }
    }

    if (inLen - tagLen > 0) {
        if(0 == (*OSSL_DecryptUpdate)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen - tagLen)) {
            printErrors();
            (*OSSL_CIPHER_CTX_free)(ctx);
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            if (inLen > 0) {
                (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            }
            if (aadLen > 0) {
                (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
            }
            return -1;
        }
        plaintext_len = len;
    }

    if (0 == (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, inputNative + inOffset + inLen - tagLen)) {
        printErrors();
        (*OSSL_CIPHER_CTX_free)(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        if (aadLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        }
        return -1;
    }


    ret = (*OSSL_DecryptFinal)(ctx, outputNative + outOffset + len, &len);

    (*OSSL_CIPHER_CTX_free)(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    }

    if (aadLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
    }

    if (ret > 0) {
        /* Successful Decryption */
        plaintext_len += len;
        return (jint)plaintext_len;
    } else {
        /* Tag Mismatch */
        return -2;
    }
}

BIGNUM* convertJavaBItoBN(unsigned char* in, int len);

/* Create an RSA Public Key
 * Returns -1 on error
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    createRSAPublicKey
 * Signature: ([BI[BI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_createRSAPublicKey
  (JNIEnv *env, jclass obj, jbyteArray n, jint nLen, jbyteArray e, jint eLen) {

    unsigned char* nNative = NULL;
    unsigned char* eNative = NULL;
    RSA* publicRSAKey = NULL;
    BIGNUM* nBN = NULL;
    BIGNUM* eBN = NULL;
    int ret = 0;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (NULL == nNative) {
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (NULL == eNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        return -1;
    }

    publicRSAKey = (*OSSL_RSA_new)();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);

    if ((NULL == publicRSAKey) || (NULL == nBN) || (NULL == eBN)) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_key)(publicRSAKey, nBN, eBN, NULL);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);

    if (0 == ret) {
        return -1;
    }

    return (jlong)(intptr_t)publicRSAKey;
}

/* Create an RSA Private CRT Key
 * Returns -1 on error
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    createRSAPrivateCrtKey
 * Signature: ([BI[BI[BI[BI[BI[BI[BI[BI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_createRSAPrivateCrtKey
  (JNIEnv *env, jclass obj, jbyteArray n, jint nLen, jbyteArray d, jint dLen, jbyteArray e, jint eLen, jbyteArray p, jint pLen, jbyteArray q, jint qLen, jbyteArray dp, jint dpLen, jbyteArray dq, jint dqLen, jbyteArray qinv, jint qinvLen) {
    unsigned char* nNative = NULL;
    unsigned char* dNative = NULL;
    unsigned char* eNative = NULL;
    unsigned char* pNative = NULL;
    unsigned char* qNative = NULL;
    unsigned char* dpNative = NULL;
    unsigned char* dqNative = NULL;
    unsigned char* qinvNative = NULL;
    RSA* privateRSACrtKey = NULL;
    BIGNUM* nBN = NULL;
    BIGNUM* eBN = NULL;
    BIGNUM* dBN = NULL;
    BIGNUM* pBN = NULL;
    BIGNUM* qBN = NULL;
    BIGNUM* dpBN = NULL;
    BIGNUM* dqBN = NULL;
    BIGNUM* qinvBN = NULL;

    int ret = 0;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (NULL == nNative) {
        return -1;
    }

    dNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, d, 0));
    if (NULL == dNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (NULL == eNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        return -1;
    }

    pNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, p, 0));
    if (NULL == pNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        return -1;
    }

    qNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, q, 0));
    if (NULL == qNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        return -1;
    }

    dpNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dp, 0));
    if (NULL == dpNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        return -1;
    }

    dqNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dq, 0));
    if (NULL == dqNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        return -1;
    }

    qinvNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, qinv, 0));
    if (NULL == qinvNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        return -1;
    }

    privateRSACrtKey = (*OSSL_RSA_new)();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);
    dBN = convertJavaBItoBN(dNative, dLen);

    if (NULL == privateRSACrtKey || NULL == nBN || NULL == eBN || NULL == dBN) {

        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_key)(privateRSACrtKey, nBN, eBN, dBN);

    pBN = convertJavaBItoBN(pNative, pLen);
    qBN = convertJavaBItoBN(qNative, qLen);

    if (0 == ret || NULL == pBN || NULL == qBN) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_factors)(privateRSACrtKey, pBN, qBN);

    dpBN = convertJavaBItoBN(dpNative, dpLen);
    dqBN = convertJavaBItoBN(dqNative, dqLen);
    qinvBN = convertJavaBItoBN(qinvNative, qinvLen);

    if (0 == ret || NULL == dpBN || NULL == dqBN || NULL == qinvBN) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_crt_params)(privateRSACrtKey, dpBN, dqBN, qinvBN);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);

    if (0 == ret) {
        return -1;
    }

    return (jlong)(intptr_t)privateRSACrtKey;
}

/* Free RSA Public/Private Key
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    destroyRSAKey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_destroyRSAKey
  (JNIEnv *env, jclass obj, jlong rsaKey) {
    RSA* rsaKey2 = (RSA*)(intptr_t)rsaKey;
    if (NULL != rsaKey2) {
        (*OSSL_RSA_free)(rsaKey2);
    }
}

/* RSAEP Cryptographic Primitive, RSA Public Key operation
 * Returns -1 on error
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    RSAEP
 * Signature: ([BI[BJ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_RSAEP
  (JNIEnv *env, jclass obj, jbyteArray k, jint kLen, jbyteArray m, jlong publicRSAKey) {

    unsigned char* kNative = NULL;
    unsigned char* mNative = NULL;
    RSA* rsaKey = NULL;
    int msg_len = 0;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (NULL == kNative) {
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (NULL == mNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
        return -1;
    }

    rsaKey = (RSA*)publicRSAKey;

    // OSSL_RSA_public_decrypt returns -1 on error
    msg_len = (*OSSL_RSA_public_decrypt)(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, m, mNative, 0);
    return (jint)msg_len;
}

/* RSADP Cryptographic Primitive, RSA Private Key operation
 * Returns -1 on error
 * The param verify is -1 for 'no verify', otherwise it is size of m (with verify)
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    RSADP
 * Signature: ([BI[BIJ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_RSADP
  (JNIEnv *env, jclass obj, jbyteArray k, jint kLen, jbyteArray m, jint verify, jlong privateRSAKey) {

    unsigned char* kNative = NULL;
    unsigned char* mNative = NULL;
    int msg_len = 0;
    int msg_len2 = 0;
    unsigned char* k2 = NULL;
    RSA* rsaKey = NULL;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (NULL == kNative) {
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (NULL == mNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
        return -1;
    }

    rsaKey = (RSA*)(intptr_t)privateRSAKey;

    // OSSL_RSA_private_encrypt returns -1 on error
    msg_len = (*OSSL_RSA_private_encrypt)(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    if ((-1 != verify) && (-1 != msg_len)) {
        if (verify == kLen) {
            k2 = malloc(kLen * (sizeof(unsigned char)));
            if (NULL != k2) {

                //mNative is size 'verify'
                msg_len2 = (*OSSL_RSA_public_decrypt)(verify, mNative, k2, rsaKey, RSA_NO_PADDING);
                if (-1 != msg_len2) {

                    int i;
                    for (i = 0; i < verify; i++) {
                        if (kNative[i] != k2[i]) {
                            msg_len = -2;
                            break;
                        }
                    }
                } else {
                    msg_len = -1;
                }
                free(k2);
            } else {
                msg_len = -1;
            }
        } else {
            msg_len = -2;
        }
    }

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, m, mNative, 0);

    return (jint)msg_len;
}

/*
 * Converts 2's complement representation of a big integer
 * into an OpenSSL BIGNUM
 */
BIGNUM* convertJavaBItoBN(unsigned char* in, int len) {
    // first bit is neg
    int neg = (in[0] & 0x80);
    int c = 1; // carry bit
    int i = 0;
    BIGNUM* bn = NULL;
    if (0 != neg) {
        // number is negative in two's complement form
        // need to extract magnitude
        for (i = len - 1; i >= 0; i--) {
            in[i] ^= 0xff; // flip bits
            if (c) { // add 1 for as long as needed
                c = 0 == (++in[i]);
            }
        }
    }
    bn = (*OSSL_BN_bin2bn)(in, len, NULL);
    if (bn != NULL) {
        (*OSSL_BN_set_negative)(bn, neg);
    }
    return bn;
}

typedef struct rsa_st102 {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of aEVP_PKEY, it is set to 0
     */
    int pad;
    long version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
}OSSL102_RSA;

/* 
 * Compatibility Layer for RSA algorithim using OpenSSL 1.0.2
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Compatibility_Layer
 */
int OSSL102_RSA_set0_key(RSA *r2, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    OSSL102_RSA* r = (OSSL102_RSA *)r2;
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((NULL == r->n && NULL == n)
        || (NULL == r->e && NULL == e))
        return 0;

    if (NULL != n) {
        (*OSSL_BN_free)(r->n);
        r->n = n;
    }
    if (NULL != e) {
        (*OSSL_BN_free)(r->e);
        r->e = e;
    }
    if (NULL != d) {
        (*OSSL_BN_free)(r->d);
        r->d = d;
    }

    return 1;
}

int OSSL102_RSA_set0_factors(RSA *r2, BIGNUM *p, BIGNUM *q)
{
    OSSL102_RSA* r = (OSSL102_RSA *)r2;
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((NULL == r->p && NULL == p)
        || (NULL == r->q && NULL == q))
        return 0;

    if (NULL != p) {
        (*OSSL_BN_free)(r->p);
        r->p = p;
    }
    if (NULL != q) {
        (*OSSL_BN_free)(r->q);
        r->q = q;
    }

    return 1;
}

int OSSL102_RSA_set0_crt_params(RSA *r2, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    OSSL102_RSA* r = (OSSL102_RSA *)r2;
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((NULL == r->dmp1 && NULL == dmp1)
        || (NULL == r->dmq1 && NULL == dmq1)
        || (NULL == r->iqmp && NULL == iqmp))
        return 0;

    if (NULL != dmp1) {
        (*OSSL_BN_free)(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (NULL != dmq1) {
        (*OSSL_BN_free)(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (NULL != iqmp) {
        (*OSSL_BN_free)(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

