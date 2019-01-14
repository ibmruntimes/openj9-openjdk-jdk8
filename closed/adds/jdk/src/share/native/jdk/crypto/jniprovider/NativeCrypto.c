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

#include <assert.h>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"
#include "NativeCrypto_md.h"

//Header for RSA algorithm using 1.0.2 OpenSSL
int OSSL102_RSA_set0_key(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
int OSSL102_RSA_set0_factors(RSA *, BIGNUM *, BIGNUM *);
int OSSL102_RSA_set0_crt_params(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
typedef struct rsa_st {
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


//Define pointers for OpenSSL functions to handle Errors.
char * (* OSSL_error_string) (unsigned long, char *);
unsigned long (* OSSL_get_error) (void);

//Define pointers for OpenSSL functions to handle Message Digest algorithms.
const EVP_MD* (* OSSL_sha1) (void);
const EVP_MD* (* OSSL_sha256) (void);
const EVP_MD* (* OSSL_sha224) (void);
const EVP_MD* (* OSSL_sha384) (void);
const EVP_MD* (* OSSL_sha512) (void);
EVP_MD_CTX* (* OSSL_MD_CTX_new) (void);
int (* OSSL_DigestInit_ex) (EVP_MD_CTX *, const EVP_MD *, ENGINE *);
int (* OSSL_MD_CTX_copy_ex) (EVP_MD_CTX *, const EVP_MD_CTX *);
int (* OSSL_DigestUpdate) (EVP_MD_CTX *, const void *, size_t);
int (* OSSL_DigestFinal_ex) (EVP_MD_CTX *, unsigned char *, unsigned int *);
int (* OSSL_MD_CTX_reset) (EVP_MD_CTX *);

//Define pointers for OpenSSL functions to handle CBC and GCM Cipher algorithms.
EVP_CIPHER_CTX* (* OSSL_CIPHER_CTX_new) (void);
void (* OSSL_CIPHER_CTX_free) (EVP_CIPHER_CTX *);
const EVP_CIPHER* (* OSSL_aes_128_cbc) (void);
const EVP_CIPHER* (* OSSL_aes_192_cbc) (void);
const EVP_CIPHER* (* OSSL_aes_256_cbc) (void);
int (* OSSL_CipherInit_ex) (EVP_CIPHER_CTX *, const EVP_CIPHER *,
                              ENGINE *, const unsigned char *, const unsigned char *, int);
int (* OSSL_CIPHER_CTX_set_padding) (EVP_CIPHER_CTX *, int);
int (* OSSL_CipherUpdate) (EVP_CIPHER_CTX *, unsigned char *, int *,
                              const unsigned char *, int);
int (* OSSL_CipherFinal_ex) (EVP_CIPHER_CTX *, unsigned char *, int *);

//Define pointers for OpenSSL functions to handle GCM algorithm.
const EVP_CIPHER* (* OSSL_aes_128_gcm) (void);
const EVP_CIPHER* (* OSSL_aes_192_gcm) (void);
const EVP_CIPHER* (* OSSL_aes_256_gcm) (void);
int (* OSSL_CIPHER_CTX_ctrl) (EVP_CIPHER_CTX *, int, int, void *);
int (* OSSL_DecryptInit_ex) (EVP_CIPHER_CTX *, const EVP_CIPHER *,
                             ENGINE *, const unsigned char *, const unsigned char *);
int (* OSSL_DecryptUpdate) (EVP_CIPHER_CTX *, unsigned char *, int *,
                             const unsigned char *, int);
int (* OSSL_DecryptFinal) (EVP_CIPHER_CTX *, unsigned char *, int *);

//Define pointers for OpenSSL functions to handle RSA algorithm.
RSA* (* OSSL_RSA_new) (void);
int (* OSSL_RSA_set0_key) (RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
int (* OSSL_RSA_set0_factors) (RSA *, BIGNUM *, BIGNUM *);
int (* OSSL_RSA_set0_crt_params) (RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
void (* OSSL_RSA_free) (RSA *);
int (* OSSL_RSA_public_decrypt) (int, const unsigned char *, unsigned char *, RSA *, int);
int (* OSSL_RSA_private_encrypt) (int, const unsigned char *, unsigned char *, RSA *, int);
BIGNUM* (* OSSL_BN_bin2bn) (const unsigned char *, int, BIGNUM *);
void (* OSSL_BN_set_negative) (BIGNUM *, int);
void (* OSSL_BN_free) (BIGNUM *);

/* Structure for OpenSSL Digest context */
typedef struct OpenSSLMDContext {
        EVP_MD_CTX *ctx;
        const EVP_MD *digestAlg;
        unsigned char* nativeBuffer;
} OpenSSLMDContext;

/* Structure for OpenSSL Cipher context */
typedef struct OpenSSLCipherContext {
        unsigned char* nativeBuffer;
        unsigned char* nativeBuffer2;
        EVP_CIPHER_CTX *ctx;
        const EVP_CIPHER* evp_cipher_128;
        const EVP_CIPHER* evp_cipher_256;
} OpenSSLCipherContext;

/* Handle errors from OpenSSL calls */
static void handleErrors(void) {
    unsigned long errCode;

    printf("An error occurred\n");

    while(errCode = (*OSSL_get_error)())
    {
        char *err = (*OSSL_error_string)(errCode, NULL);
        printf("Generating error message\n" );
        printf("%s\n", err);
    }
    abort();
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    loadCrypto
 * Signature: ()V
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_loadCrypto
  (JNIEnv *env, jclass thisObj){

    void *handle;
    char *error;

     // Determine the version of OpenSSL.
    char * (*OSSL_version) (int);
    char * openssl_version;
    int ossl_ver;

    // Load OpenSSL Crypto library
    handle = load_crypto_library();
    if (handle == NULL) {
        fprintf(stderr, "FAILED TO LOAD OPENSSL CRYPTO LIBRARY\n");
        fflush(stderr);
        return -1;
    }

    // Different symbols are used by OpenSSL with 1.0 and 1.1.
    // The symbol 'OpenSSL_version' is used by OpenSSL 1.1 where as
    // the symbol "SSLeay_version" is used by OpenSSL 1.0.
    // Currently only openssl 1.0.2 and 1.1.0 and 1.1.1 are supported.
    OSSL_version = (char * (*))find_crypto_symbol(handle, "OpenSSL_version");

    if (OSSL_version == NULL)  {
        OSSL_version = (char *)find_crypto_symbol(handle, "SSLeay_version");

        if (OSSL_version == NULL)  {
            fprintf(stderr, "Only openssl 1.0.2 and 1.1.0 and 1.1.1 are supported\n");
            fflush(stderr);
            unload_crypto_library(handle);
            return -1;
        } else {
            openssl_version = (*OSSL_version)(0); //get OPENSSL_VERSION
            //Ensure the OpenSSL version is "OpenSSL 1.0.2"
            if (strncmp(openssl_version, "OpenSSL 1.0.2", 13) != 0) {
                fprintf(stderr, "Incompatable OpenSSL version: %s\n", openssl_version);
                fflush(stderr);
                unload_crypto_library(handle);
                return -1;
            }
            ossl_ver = 0;
        }
    } else {
        openssl_version = (*OSSL_version)(0); //get OPENSSL_VERSION
        //Ensure the OpenSSL version is "OpenSSL 1.1.0" or "OpenSSL 1.1.0".
        if (strncmp(openssl_version, "OpenSSL 1.1.0", 13) != 0 &&
            strncmp(openssl_version, "OpenSSL 1.1.1", 13) != 0) {
            fprintf(stderr, "Incompatable OpenSSL version: %s\n", openssl_version);
            fflush(stderr);
            unload_crypto_library(handle);
            return -1;
        }
        ossl_ver = 1;
    }
    
    // Load the function symbols for OpenSSL errors.
    OSSL_error_string = (char * (*)(unsigned long, char *))find_crypto_symbol(handle, "ERR_error_string");
    OSSL_get_error = (unsigned long (*)(void))find_crypto_symbol(handle, "ERR_get_error");

    //Load the function symbols for OpenSSL Message Digest algorithms.
    OSSL_sha1 = (const EVP_MD* *)find_crypto_symbol(handle, "EVP_sha1");
    OSSL_sha256 = (const EVP_MD* *)find_crypto_symbol(handle, "EVP_sha256");
    OSSL_sha224 = (const EVP_MD* *)find_crypto_symbol(handle, "EVP_sha224");
    OSSL_sha384 = (const EVP_MD* *)find_crypto_symbol(handle, "EVP_sha384");
    OSSL_sha512 = (const EVP_MD* *)find_crypto_symbol(handle, "EVP_sha512");

    if (ossl_ver == 1) {
        OSSL_MD_CTX_new = (EVP_MD_CTX* *)find_crypto_symbol(handle, "EVP_MD_CTX_new");
        OSSL_MD_CTX_reset = (int *)find_crypto_symbol(handle, "EVP_MD_CTX_reset");
    } else {
        OSSL_MD_CTX_new = (EVP_MD_CTX* *)find_crypto_symbol(handle, "EVP_MD_CTX_create");
        OSSL_MD_CTX_reset = (int *)find_crypto_symbol(handle, "EVP_MD_CTX_cleanup");
    }

    OSSL_DigestInit_ex = (int *)find_crypto_symbol(handle, "EVP_DigestInit_ex");
    OSSL_MD_CTX_copy_ex = (int *)find_crypto_symbol(handle, "EVP_MD_CTX_copy_ex");
    OSSL_DigestUpdate = (int *)find_crypto_symbol(handle, "EVP_DigestUpdate");
    OSSL_DigestFinal_ex = (int *)find_crypto_symbol(handle, "EVP_DigestFinal_ex");

    //Load the function symbols for OpenSSL CBC and GCM Cipher algorithms.
    OSSL_CIPHER_CTX_new = (EVP_CIPHER_CTX* *)find_crypto_symbol(handle, "EVP_CIPHER_CTX_new");
    OSSL_CIPHER_CTX_free = (void *)find_crypto_symbol(handle, "EVP_CIPHER_CTX_free");
    OSSL_aes_128_cbc = (const EVP_CIPHER* *)find_crypto_symbol(handle, "EVP_aes_128_cbc");
    OSSL_aes_192_cbc = (const EVP_CIPHER* *)find_crypto_symbol(handle, "EVP_aes_192_cbc");
    OSSL_aes_256_cbc = (const EVP_CIPHER* *)find_crypto_symbol(handle, "EVP_aes_256_cbc");
    OSSL_CipherInit_ex = (int *)find_crypto_symbol(handle, "EVP_CipherInit_ex");
    OSSL_CIPHER_CTX_set_padding = (int *)find_crypto_symbol(handle, "EVP_CIPHER_CTX_set_padding");
    OSSL_CipherUpdate = (int *)find_crypto_symbol(handle, "EVP_CipherUpdate");
    OSSL_CipherFinal_ex = (int *)find_crypto_symbol(handle, "EVP_CipherFinal_ex");
    OSSL_aes_128_gcm = (const EVP_CIPHER* *)find_crypto_symbol(handle, "EVP_aes_128_gcm");
    OSSL_aes_192_gcm = (const EVP_CIPHER* *)find_crypto_symbol(handle, "EVP_aes_192_gcm");
    OSSL_aes_256_gcm = (const EVP_CIPHER* *)find_crypto_symbol(handle, "EVP_aes_256_gcm");
    OSSL_CIPHER_CTX_ctrl = (int *)find_crypto_symbol(handle, "EVP_CIPHER_CTX_ctrl");
    OSSL_DecryptInit_ex = (int *)find_crypto_symbol(handle, "EVP_DecryptInit_ex");
    OSSL_DecryptUpdate = (int *)find_crypto_symbol(handle, "EVP_DecryptUpdate");
    OSSL_DecryptFinal = (int *)find_crypto_symbol(handle, "EVP_DecryptFinal");

    //Load the functions symbols for Openssl RSA algorithm.
    OSSL_RSA_new = (RSA* *)find_crypto_symbol(handle, "RSA_new");

    if (ossl_ver == 1) {
        OSSL_RSA_set0_key = (int *)find_crypto_symbol(handle, "RSA_set0_key");
        OSSL_RSA_set0_factors = (int *)find_crypto_symbol(handle, "RSA_set0_factors");
        OSSL_RSA_set0_crt_params = (int *)find_crypto_symbol(handle, "RSA_set0_crt_params");
    } else {
        OSSL_RSA_set0_key = &OSSL102_RSA_set0_key;
        OSSL_RSA_set0_factors = &OSSL102_RSA_set0_factors;
        OSSL_RSA_set0_crt_params = &OSSL102_RSA_set0_crt_params;
    }

    OSSL_RSA_free = (void *)find_crypto_symbol(handle, "RSA_free");
    OSSL_RSA_public_decrypt = (int *)find_crypto_symbol(handle, "RSA_public_decrypt");
    OSSL_RSA_private_encrypt = (int *)find_crypto_symbol(handle, "RSA_private_decrypt");
    OSSL_BN_bin2bn = (BIGNUM* *)find_crypto_symbol(handle, "BN_bin2bn");
    OSSL_BN_set_negative = (void *)find_crypto_symbol(handle, "BN_set_negative");
    OSSL_BN_free = (void *)find_crypto_symbol(handle, "BN_free");

    if ((OSSL_error_string == NULL) ||
        (OSSL_get_error == NULL) ||
        (OSSL_sha1 == NULL) ||
        (OSSL_sha256 == NULL) ||
        (OSSL_sha224 == NULL) ||
        (OSSL_sha384 == NULL) ||
        (OSSL_sha512 == NULL) ||
        (OSSL_MD_CTX_new == NULL) ||
        (OSSL_MD_CTX_reset == NULL) ||
        (OSSL_DigestInit_ex == NULL) ||
        (OSSL_MD_CTX_copy_ex == NULL) ||
        (OSSL_DigestUpdate == NULL) ||
        (OSSL_DigestFinal_ex == NULL) ||
        (OSSL_CIPHER_CTX_new == NULL) ||
        (OSSL_CIPHER_CTX_free == NULL) ||
        (OSSL_aes_128_cbc == NULL) ||
        (OSSL_aes_192_cbc == NULL) ||
        (OSSL_aes_256_cbc == NULL) ||
        (OSSL_CipherInit_ex == NULL) ||
        (OSSL_CIPHER_CTX_set_padding == NULL) ||
        (OSSL_CipherUpdate == NULL) ||
        (OSSL_CipherFinal_ex == NULL) ||
        (OSSL_aes_128_gcm == NULL) ||
        (OSSL_aes_192_gcm == NULL) ||
        (OSSL_aes_256_gcm == NULL) ||
        (OSSL_CIPHER_CTX_ctrl == NULL) ||
        (OSSL_DecryptInit_ex == NULL) ||
        (OSSL_DecryptUpdate == NULL) ||
        (OSSL_DecryptFinal == NULL) ||
        (OSSL_RSA_new == NULL) ||
        (OSSL_RSA_set0_key == NULL) ||
        (OSSL_RSA_set0_factors == NULL) ||
        (OSSL_RSA_set0_crt_params == NULL) ||
        (OSSL_RSA_free == NULL) ||
        (OSSL_RSA_public_decrypt == NULL) ||
        (OSSL_RSA_private_encrypt == NULL) ||
        (OSSL_BN_bin2bn == NULL) ||
        (OSSL_BN_set_negative == NULL) ||
        (OSSL_BN_free == NULL)) {
        fprintf(stderr, "One or more of the required symbols are missing in the crypto library\n");
        fflush(stderr);
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

    EVP_MD_CTX *ctx;
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
            assert(0);
    }

    if((ctx = (*OSSL_MD_CTX_new)()) == NULL)
        handleErrors();

    if(1 != (*OSSL_DigestInit_ex)(ctx, digestAlg, NULL))
        handleErrors();

    context = malloc(sizeof(OpenSSLMDContext));
    context->ctx = ctx;
    context->digestAlg = digestAlg;

    if (copyContext != 0) {
        EVP_MD_CTX *contextToCopy = ((OpenSSLMDContext*) copyContext)->ctx;
        (*OSSL_MD_CTX_copy_ex)(ctx,contextToCopy);
    }


    return (jlong)context;
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

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;

    if (message == NULL) {
        // Data passed in through direct byte buffer
        if (1 != (*OSSL_DigestUpdate)(context->ctx, context->nativeBuffer, messageLen))
            handleErrors();
    } else {
        unsigned char* messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
        if (messageNative == NULL) {
            return -1;
        }

        if (1 != (*OSSL_DigestUpdate)(context->ctx, (messageNative + messageOffset), messageLen))
            handleErrors();

        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, 0);
    }

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

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;

    unsigned int size;
    unsigned char* messageNative;
    unsigned char* digestNative;

    if (message != NULL) {
        messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
        if (messageNative == NULL) {
            return -1;
        }

        if (1 != (*OSSL_DigestUpdate)(context->ctx, (messageNative + messageOffset), messageLen))
            handleErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, 0);
    }

    digestNative = (*env)->GetPrimitiveArrayCritical(env, digest, 0);
    if (digestNative == NULL) {
        return -1;
    }

    if (1 != (*OSSL_DigestFinal_ex)(context->ctx, (digestNative + digestOffset), &size))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, 0);

    (*OSSL_MD_CTX_reset)(context->ctx);

    if (1 != (*OSSL_DigestInit_ex)(context->ctx, context->digestAlg, NULL))
        handleErrors();

    return size;
}

/* Create Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCCreateContext
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCCreateContext
  (JNIEnv *env, jclass thisObj, jlong nativeBuffer, jlong nativeBuffer2) {

    EVP_CIPHER_CTX *ctx = NULL;
    OpenSSLCipherContext *context = NULL;

    /* Create and initialise the context */
    if ((ctx = (*OSSL_CIPHER_CTX_new)()) == NULL)
        handleErrors();

    context = malloc(sizeof(OpenSSLCipherContext));
    context->nativeBuffer = (unsigned char*)nativeBuffer;
    context->nativeBuffer2 = (unsigned char*)nativeBuffer2;
    context->ctx = ctx;

    return (jlong)context;
}

/* Destroy Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCDestroyContext
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCDestroyContext
  (JNIEnv *env, jclass thisObj, jlong c) {

     OpenSSLCipherContext *context = (OpenSSLCipherContext*) c;

     (*OSSL_CIPHER_CTX_free)(context->ctx);
     free(context);
     return 0;
}

/* Initialize CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCInit
 * Signature: (JI[BI[BI)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCInit
  (JNIEnv *env, jclass thisObj, jlong c, jint mode, jbyteArray iv, jint iv_len,
  jbyteArray key, jint key_len) {

    EVP_CIPHER_CTX *ctx = ((OpenSSLCipherContext*)c)->ctx;
    unsigned char* ivNative;
    unsigned char* keyNative;
    const EVP_CIPHER * evp_cipher1 = NULL;

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
            assert(32);
    }

    ivNative = (unsigned char*)((*env)->GetByteArrayElements(env, iv, 0));
    if (ivNative == NULL)
        return;

    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, 0));
    if (keyNative == NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        return;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_cipher1, NULL, keyNative, ivNative, mode))
        handleErrors();

    (*OSSL_CIPHER_CTX_set_padding)(ctx, 0);

    (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
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

    EVP_CIPHER_CTX *ctx = (((OpenSSLCipherContext*)c)->ctx);
    int outputLen = -1;

    unsigned char* inputNative;
    unsigned char* outputNative;

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (inputNative == NULL)
        return -1;

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (outputNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
        return -1;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return outputLen;
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

    EVP_CIPHER_CTX *ctx = (((OpenSSLCipherContext*)c)->ctx);

    unsigned char buf[16];

    int outputLen = -1;
    int outputLen1 = -1;

    unsigned char* inputNative;
    unsigned char* outputNative;

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (inputNative == NULL)
        return -1;

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (outputNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
        return -1;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen))
        handleErrors();

    if (1 != (*OSSL_CipherFinal_ex)(ctx, buf, &outputLen1))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return outputLen+outputLen1;
}

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
    int len, len_cipher = 0;
    unsigned char* keyNative;
    unsigned char* ivNative;
    unsigned char* outputNative;
    unsigned char* aadNative;

    EVP_CIPHER_CTX* ctx = NULL;
    const EVP_CIPHER* evp_gcm_cipher = NULL;

    keyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (keyNative == NULL) {
        return -1;
    }

    ivNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv, 0));
    if (ivNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
        return -1;
    }

    aadNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
    if (aadNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (outputNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
        return -1;
    }

    if (inLen > 0) {
        inputNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (inputNative == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);
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
            assert(32);
    }

    ctx = (*OSSL_CIPHER_CTX_new)();
    if(1 != (*OSSL_CipherInit_ex)(ctx, evp_gcm_cipher, NULL, NULL, NULL, 1 )) /* 1 - Encrypt mode 0 Decrypt Mode*/
        handleErrors();

    if(1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
        handleErrors();

    if(1 != (*OSSL_CipherInit_ex)(ctx, NULL, NULL, keyNative, ivNative, -1))
        handleErrors();

    /* provide AAD */
    if(1 != (*OSSL_CipherUpdate)(ctx, NULL, &len, aadNative, aadLen))
        handleErrors();

    /* encrypt plaintext and obtain ciphertext */
    if (inLen > 0) {
        if(1 != (*OSSL_CipherUpdate)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen))
            handleErrors();
        len_cipher = len;
    }

    /* finalize the encryption */
    if(1 != (*OSSL_CipherFinal_ex)(ctx, outputNative + outOffset + len_cipher, &len))
        handleErrors();

    /* Get the tag, place it at the end of the cipherText buffer */
    if(1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, outputNative + outOffset + len + len_cipher))
        handleErrors();

    (*OSSL_CIPHER_CTX_free)(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative,   0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative,    0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative,0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative,  0);
    return len_cipher;
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
    int ret, len, plaintext_len = 0;
    unsigned char* keyNative;
    unsigned char* ivNative;
    unsigned char* outputNative;
    EVP_CIPHER_CTX* ctx = NULL;
    const EVP_CIPHER* evp_gcm_cipher = NULL;

    keyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (keyNative == NULL)
        return -1;

    ivNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv, 0));
    if (ivNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (outputNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
        return -1;
    }

    if (inLen > 0) {
        inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (inputNative == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);
            return -1;
        }
    }

    if (aadLen > 0) {
        aadNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
        if (aadNative == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);
            if (inLen > 0)
                (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
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
            assert(32);
    }

    ctx = (*OSSL_CIPHER_CTX_new)();

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_gcm_cipher, NULL, NULL, NULL, 0 )) /* 1 - Encrypt mode 0 Decrypt Mode*/
        handleErrors();

    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
        handleErrors();

    /* Initialise key and IV */
    if (1 != (*OSSL_DecryptInit_ex)(ctx, NULL, NULL, keyNative, ivNative))
        handleErrors();

    /* Provide any AAD data */
    if (aadLen > 0) {
        if (1 != (*OSSL_DecryptUpdate)(ctx, NULL, &len, aadNative, aadLen))
            handleErrors();
    }

    if (inLen - tagLen > 0) {
        if (1 != (*OSSL_DecryptUpdate)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen - tagLen))
            handleErrors();

        plaintext_len = len;
    }

    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, inputNative + inOffset + inLen - tagLen))
        handleErrors();

    ret = (*OSSL_DecryptFinal)(ctx, outputNative + outOffset + len, &len);

    (*OSSL_CIPHER_CTX_free)(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative,   0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative,    0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative,0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    if (aadLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative,  0);
    }

    if (ret > 0) {
        /* Successful Decryption */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Tag Mismatch */
        return -1;
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

    unsigned char* nNative;
    unsigned char* eNative;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (nNative == NULL) {
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (eNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        return -1;
    }

    RSA* publicRSAKey = (*OSSL_RSA_new)();

    BIGNUM* nBN = convertJavaBItoBN(nNative,nLen);
    BIGNUM* eBN = convertJavaBItoBN(eNative,eLen);
    
    if (publicRSAKey == NULL || nBN == NULL || eBN == NULL){
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);
        return -1;
    }

    int ret = (*OSSL_RSA_set0_key)(publicRSAKey, nBN, eBN, NULL);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);

    if (ret == 0){
        return -1;
    }

    return (long)publicRSAKey;
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
    unsigned char* nNative;
    unsigned char* dNative;
    unsigned char* eNative;
    unsigned char* pNative;
    unsigned char* qNative;
    unsigned char* dpNative;
    unsigned char* dqNative;
    unsigned char* qinvNative;

    nNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (nNative == NULL) {
        return -1;
    }

    dNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, d, 0));
    if (dNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        return -1;
    }

    eNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (eNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative,  0);
        return -1;
    }

    pNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, p, 0));
    if (pNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);
        return -1;
    }

    qNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, q, 0));
    if (qNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative,  0);
        return -1;
    }

    dpNative   = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dp, 0));
    if (dpNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative,  0);
        return -1;
    }

    dqNative   = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dq, 0));
    if (dqNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative,  0);
        return -1;
    }

    qinvNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, qinv, 0));
    if (qinvNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative,  0);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative,  0);
        return -1;
    }

    RSA* privateRSACrtKey = (*OSSL_RSA_new)();

    BIGNUM* nBN = convertJavaBItoBN(nNative,nLen);
    BIGNUM* eBN = convertJavaBItoBN(eNative,eLen);
    BIGNUM* dBN = convertJavaBItoBN(dNative,dLen);

    if (privateRSACrtKey == NULL || nBN == NULL || eBN == NULL || dBN == NULL){

        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, 0);
        return -1;
    }

    int ret;

    ret = (*OSSL_RSA_set0_key)(privateRSACrtKey, nBN, eBN, dBN);

    BIGNUM* pBN = convertJavaBItoBN(pNative,pLen);
    BIGNUM* qBN = convertJavaBItoBN(qNative,qLen);

    if (ret == 0 || pBN == NULL || qBN == NULL){
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, 0);
        return -1;
    }

    ret = (*OSSL_RSA_set0_factors)(privateRSACrtKey, pBN, qBN);

    BIGNUM* dpBN   = convertJavaBItoBN(dpNative,  dpLen);
    BIGNUM* dqBN   = convertJavaBItoBN(dqNative,  dqLen);
    BIGNUM* qinvBN = convertJavaBItoBN(qinvNative,qinvLen);

    if (ret == 0 || dpBN == NULL || dqBN == NULL || qinvBN == NULL){
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, 0);
        return -1;
    }

    ret = (*OSSL_RSA_set0_crt_params)(privateRSACrtKey, dpBN, dqBN, qinvBN);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, 0);
    
    if (ret == 0)
        return -1;

    return (long)privateRSACrtKey;
}

/* Free RSA Public/Private Key
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    destroyRSAKey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_destroyRSAKey
  (JNIEnv *env, jclass obj, jlong rsaKey) {
    (*OSSL_RSA_free)((RSA*)rsaKey);
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

    unsigned char* kNative;
    unsigned char* mNative;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (kNative == NULL){
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (mNative == NULL){
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative,  0);
        return -1;
    }

    RSA* rsaKey = (RSA*)publicRSAKey;

    // OSSL_RSA_public_decrypt returns -1 on error
    int msg_len = (*OSSL_RSA_public_decrypt)(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative,  0);
    (*env)->ReleasePrimitiveArrayCritical(env, m, mNative,  0);
    return msg_len;
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

    unsigned char* kNative;
    unsigned char* mNative;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (kNative == NULL){
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (mNative == NULL){
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative,  0);
        return -1;
    }

    RSA* rsaKey = (RSA*)privateRSAKey;

    // OSSL_RSA_private_encrypt returns -1 on error
    int msg_len = (*OSSL_RSA_private_encrypt)(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative,  0);
    (*env)->ReleasePrimitiveArrayCritical(env, m, mNative,  0);

    if (verify != -1 && msg_len != -1){
        if (verify != kLen){
            return -2;
        }
        unsigned char k2[kLen];

        //mNative is size 'verify'
        int msg_len = (*OSSL_RSA_public_decrypt)(verify, mNative, k2, rsaKey, RSA_NO_PADDING);

        int i;
        for (i = 0; i < verify; i++){
            if (kNative[i] != k2[i]){
                return -2;
            }
        }
    }
    return msg_len;
}

/*
 * Converts 2's complement representation of a big integer
 * into an OpenSSL BIGNUM
 */
BIGNUM* convertJavaBItoBN(unsigned char* in, int len) {
    // first bit is neg
    int neg = (in[0] & 0x80);
    if (neg != 0) {
        // number is negative in two's complement form
        // need to extract magnitude
        int c = 1;
        int i = 0;
        for(i = len - 1; i >= 0; i--) {
            in[i] ^= 0xff; // flip bits
            if(c){ // add 1 for as long as needed
                c = (++in[i]) == 0;
            }
        }
    }
    BIGNUM* bn = (*OSSL_BN_bin2bn)(in, len, NULL);
    if (bn != NULL){
        (*OSSL_BN_set_negative)(bn, neg);
    }
    return bn;
}

/* 
 * Compatibility Layer for RSA algorithim using OpenSSL 1.0.2
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Compatibility_Layer
 */

int OSSL102_RSA_set0_key(RSA *r2, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
   OSSL102_RSA* r = (OSSL102_RSA *) r2;
   /* If the fields n and e in r are NULL, the corresponding input
    * parameters MUST be non-NULL for n and e.  d may be
    * left NULL (in case only the public key is used).
    */
   if ((r->n == NULL && n == NULL)
       || (r->e == NULL && e == NULL))
       return 0;

   if (n != NULL) {
       (*OSSL_BN_free)(r->n);
       r->n = n;
   }
   if (e != NULL) {
       (*OSSL_BN_free)(r->e);
       r->e = e;
   }
   if (d != NULL) {
       (*OSSL_BN_free)(r->d);
       r->d = d;
   }

   return 1;
}

int OSSL102_RSA_set0_factors(RSA *r2, BIGNUM *p, BIGNUM *q)
{
   OSSL102_RSA* r = (OSSL102_RSA *) r2;
   /* If the fields p and q in r are NULL, the corresponding input
    * parameters MUST be non-NULL.
    */
   if ((r->p == NULL && p == NULL)
       || (r->q == NULL && q == NULL))
       return 0;

   if (p != NULL) {
       (*OSSL_BN_free)(r->p);
       r->p = p;
   }
   if (q != NULL) {
       (*OSSL_BN_free)(r->q);
       r->q = q;
   }

   return 1;
}

int OSSL102_RSA_set0_crt_params(RSA *r2, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
   OSSL102_RSA* r = (OSSL102_RSA *) r2;
   /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
    * parameters MUST be non-NULL.
    */
   if ((r->dmp1 == NULL && dmp1 == NULL)
       || (r->dmq1 == NULL && dmq1 == NULL)
       || (r->iqmp == NULL && iqmp == NULL))
       return 0;

   if (dmp1 != NULL) {
       (*OSSL_BN_free)(r->dmp1);
       r->dmp1 = dmp1;
   }
   if (dmq1 != NULL) {
       (*OSSL_BN_free)(r->dmq1);
       r->dmq1 = dmq1;
   }
   if (iqmp != NULL) {
       (*OSSL_BN_free)(r->iqmp);
       r->iqmp = iqmp;
   }

   return 1;
}
