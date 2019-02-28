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
#include <stdlib.h>
#include <string.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"

/* Structure for OpenSSL Digest context */
typedef struct OpenSSLMDContext {
    EVP_MD_CTX *ctx;
    const EVP_MD *digestAlg;
} OpenSSLMDContext;

/* Handle errors from OpenSSL calls */
static void printErrors(void) {
    unsigned long errCode = 0;

    fprintf(stderr, "An error occurred\n");
    while(0 != (errCode = ERR_get_error()))
    {
        char err_str[120];
        ERR_error_string_n(errCode, err_str, (sizeof(err_str) / sizeof(char)));
        fprintf(stderr, "Generating error message\n" );
        fprintf(stderr, "%s\n", err_str);
    }
    fflush(stderr);
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
            digestAlg = EVP_sha1();
            break;
        case 1:
            digestAlg = EVP_sha256();
            break;
        case 2:
            digestAlg = EVP_sha224();
            break;
        case 3:
            digestAlg = EVP_sha384();
            break;
        case 4:
            digestAlg = EVP_sha512();
            break;
        default:
            return -1;
    }

    if (NULL == (ctx = EVP_MD_CTX_new())) {
        printErrors();
        return -1;
    }

    if (1 != EVP_DigestInit_ex(ctx, digestAlg, NULL)) {
        printErrors();
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    context = malloc(sizeof(OpenSSLMDContext));
    if (NULL == context) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    context->ctx = ctx;
    context->digestAlg = digestAlg;

    if (0 != copyContext) {
        EVP_MD_CTX *contextToCopy = ((OpenSSLMDContext*)(intptr_t)copyContext)->ctx;
        if (NULL == contextToCopy) {
            EVP_MD_CTX_free(ctx);
            free(context);
            return -1;
        }
        if (0 == EVP_MD_CTX_copy_ex(ctx, contextToCopy)) {
            printErrors();
            EVP_MD_CTX_free(ctx);
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

    EVP_MD_CTX_free(context->ctx);
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

    if (1 != EVP_DigestUpdate(context->ctx, (messageNative + messageOffset), messageLen)) {
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

        if (1 != EVP_DigestUpdate(context->ctx, (messageNative + messageOffset), messageLen)) {
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

    if (1 != EVP_DigestFinal_ex(context->ctx, (digestNative + digestOffset), &size)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, 0);

    EVP_MD_CTX_reset(context->ctx);

    if (1 != EVP_DigestInit_ex(context->ctx, context->digestAlg, NULL)) {
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

    EVP_MD_CTX_reset(context->ctx);

    if (1 != EVP_DigestInit_ex(context->ctx, context->digestAlg, NULL)) {
        printErrors();
    }
}

/* Create Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCCreateContext
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCCreateContext
  (JNIEnv *env, jclass thisObj) {

    EVP_CIPHER_CTX *ctx = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Create and initialise the context */
    if (NULL == (ctx = EVP_CIPHER_CTX_new())) {
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
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCDestroyContext
  (JNIEnv *env, jclass thisObj, jlong c) {

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;
    if (NULL == ctx) {
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
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
            evp_cipher1 = EVP_aes_128_cbc();
            break;
        case 24:
            evp_cipher1 = EVP_aes_192_cbc();
            break;
        case 32:
            evp_cipher1 = EVP_aes_256_cbc();
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

    if (1 != EVP_CipherInit_ex(ctx, evp_cipher1, NULL, keyNative, ivNative, mode)) {
        printErrors();
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
        return -1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

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

    if (1 != EVP_CipherUpdate(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
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

    if (1 != EVP_CipherUpdate(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    if (1 != EVP_CipherFinal_ex(ctx, buf, &outputLen1)) {
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

    if (0 == first_time_gcm) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        first_time_gcm = 1;
    }

    switch(keyLen) {
        case 16:
            evp_gcm_cipher = EVP_aes_128_gcm();
            break;
        case 24:
            evp_gcm_cipher = EVP_aes_192_gcm();
            break;
        case 32:
            evp_gcm_cipher = EVP_aes_256_gcm();
            break;
    }

    ctx = EVP_CIPHER_CTX_new();
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

    if (1 != EVP_CipherInit_ex(ctx, evp_gcm_cipher, NULL, NULL, NULL, 1 )) { /* 1 - Encrypt mode 0 Decrypt Mode*/
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }

    if (1 != EVP_CipherInit_ex(ctx, NULL, NULL, keyNative, ivNative, -1)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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
    if (1 != EVP_CipherUpdate(ctx, NULL, &len, aadNative, aadLen)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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
        if (1 != EVP_CipherUpdate(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen)) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
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
    if (1 != EVP_CipherFinal_ex(ctx, outputNative + outOffset + len_cipher, &len)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, outputNative + outOffset + len + len_cipher)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        if (inLen > 0) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        }
        return -1;
    }


    EVP_CIPHER_CTX_free(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);

    return 0;
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
    if (NULL == keyNative) {
        return -1;
    }

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
            if (inLen > 0) {
                (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            }
            return -1;
        }
    }

    if (0 == first_time_gcm) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        first_time_gcm = 1;
    }

    switch(keyLen) {
        case 16:
            evp_gcm_cipher = EVP_aes_128_gcm();
            break;
        case 24:
            evp_gcm_cipher = EVP_aes_192_gcm();
            break;
        case 32:
            evp_gcm_cipher = EVP_aes_256_gcm();
            break;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (1 != EVP_CipherInit_ex(ctx, evp_gcm_cipher, NULL, NULL, NULL, 0 )) { /* 1 - Encrypt mode 0 Decrypt Mode*/
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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
    if (0 == EVP_DecryptInit_ex(ctx, NULL, NULL, keyNative, ivNative)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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
        if (0 == EVP_DecryptUpdate(ctx, NULL, &len, aadNative, aadLen)) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
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
        if(0 == EVP_DecryptUpdate(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen - tagLen)) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
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

    if (0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, inputNative + inOffset + inLen - tagLen)) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
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


    ret = EVP_DecryptFinal(ctx, outputNative + outOffset + len, &len);

    EVP_CIPHER_CTX_free(ctx);

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

    publicRSAKey = RSA_new();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);

    if ((NULL == publicRSAKey) || (NULL == nBN) || (NULL == eBN)) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        return -1;
    }

    ret = RSA_set0_key(publicRSAKey, nBN, eBN, NULL);

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

    privateRSACrtKey = RSA_new();

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

    ret = RSA_set0_key(privateRSACrtKey, nBN, eBN, dBN);

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

    ret = RSA_set0_factors(privateRSACrtKey, pBN, qBN);

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

    ret = RSA_set0_crt_params(privateRSACrtKey, dpBN, dqBN, qinvBN);

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
        RSA_free(rsaKey2);
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

    rsaKey = (RSA*)(intptr_t)publicRSAKey;

    // OSSL_RSA_public_decrypt returns -1 on error
    msg_len = RSA_public_decrypt(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

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
    msg_len = RSA_private_encrypt(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    if ((-1 != verify) && (-1 != msg_len)) {
        if (verify == kLen) {
            k2 = malloc(kLen * (sizeof(unsigned char)));
            if (NULL != k2) {

                //mNative is size 'verify'
                msg_len2 = RSA_public_decrypt(verify, mNative, k2, rsaKey, RSA_NO_PADDING);
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
    bn = BN_bin2bn(in, len, NULL);
    if (bn != NULL) {
        BN_set_negative(bn, neg);
    }
    return bn;
}
