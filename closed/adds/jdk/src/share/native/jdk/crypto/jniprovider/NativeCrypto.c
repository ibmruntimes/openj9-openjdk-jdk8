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

#include <assert.h>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"
#include "NativeCrypto_md.h"

//Type definitions of function pointers
typedef char * OSSL_error_string_t(unsigned long, char *);
typedef unsigned long OSSL_get_error_t();
typedef const EVP_MD* OSSL_sha_t();
typedef EVP_MD_CTX* OSSL_MD_CTX_new_t();
typedef int OSSL_DigestInit_ex_t(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
typedef int OSSL_MD_CTX_copy_ex_t(EVP_MD_CTX *, const EVP_MD_CTX *);
typedef int OSSL_DigestUpdate_t(EVP_MD_CTX *, const void *, size_t);
typedef int OSSL_DigestFinal_ex_t(EVP_MD_CTX *, unsigned char *, unsigned int *);
typedef int OSSL_MD_CTX_reset_t(EVP_MD_CTX *);
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


//Define pointers for OpenSSL functions to handle Errors.
OSSL_error_string_t* OSSL_error_string;
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
    typedef const char* OSSL_version_t(int);

     // Determine the version of OpenSSL.
    OSSL_version_t* OSSL_version;
    const char * openssl_version;
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
    OSSL_version = (OSSL_version_t*)find_crypto_symbol(handle, "OpenSSL_version");

    if (OSSL_version == NULL)  {
        OSSL_version = (OSSL_version_t*)find_crypto_symbol(handle, "SSLeay_version");

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
    OSSL_error_string = (OSSL_error_string_t*)find_crypto_symbol(handle, "ERR_error_string");
    OSSL_get_error = (OSSL_get_error_t*)find_crypto_symbol(handle, "ERR_get_error");

    //Load the function symbols for OpenSSL Message Digest algorithms.
    OSSL_sha1 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha1");
    OSSL_sha256 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha256");
    OSSL_sha224 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha224");
    OSSL_sha384 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha384");
    OSSL_sha512 = (OSSL_sha_t*)find_crypto_symbol(handle, "EVP_sha512");

    if (ossl_ver == 1) {
        OSSL_MD_CTX_new = (OSSL_MD_CTX_new_t*)find_crypto_symbol(handle, "EVP_MD_CTX_new");
        OSSL_MD_CTX_reset = (OSSL_MD_CTX_reset_t*)find_crypto_symbol(handle, "EVP_MD_CTX_reset");
    } else {
        OSSL_MD_CTX_new = (OSSL_MD_CTX_new_t*)find_crypto_symbol(handle, "EVP_MD_CTX_create");
        OSSL_MD_CTX_reset = (OSSL_MD_CTX_reset_t*)find_crypto_symbol(handle, "EVP_MD_CTX_cleanup");
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
        (OSSL_DecryptFinal == NULL)) {
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
