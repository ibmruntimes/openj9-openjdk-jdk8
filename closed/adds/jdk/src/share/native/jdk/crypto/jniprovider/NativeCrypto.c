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
#include <assert.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"

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

    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("Generating error message\n" );
        printf("%s\n", err);
    }
    abort();
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
            assert(0);
    }

    if((ctx = EVP_MD_CTX_new()) == NULL)
        handleErrors();

    if(1 != EVP_DigestInit_ex(ctx, digestAlg, NULL))
        handleErrors();

    context = malloc(sizeof(OpenSSLMDContext));
    context->ctx = ctx;
    context->digestAlg = digestAlg;

    if (copyContext != 0) {
        EVP_MD_CTX *contextToCopy = ((OpenSSLMDContext*) copyContext)->ctx;
        EVP_MD_CTX_copy_ex(ctx, contextToCopy);
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

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;
    if (context == NULL) {
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

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;

    if (message == NULL) {
        // Data passed in through direct byte buffer
        if (1 != EVP_DigestUpdate(context->ctx, context->nativeBuffer, messageLen))
            handleErrors();
    } else {
        unsigned char* messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
        if (messageNative == NULL) {
            return -1;
        }

        if (1 != EVP_DigestUpdate(context->ctx, (messageNative + messageOffset), messageLen))
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

        if (1 != EVP_DigestUpdate(context->ctx, (messageNative + messageOffset), messageLen))
            handleErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, 0);
    }

    digestNative = (*env)->GetPrimitiveArrayCritical(env, digest, 0);
    if (digestNative == NULL) {
        return -1;
    }

    if (1 != EVP_DigestFinal_ex(context->ctx, (digestNative + digestOffset), &size))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, 0);

    EVP_MD_CTX_reset(context->ctx);

    if (1 != EVP_DigestInit_ex(context->ctx, context->digestAlg, NULL))
        handleErrors();

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

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;

    EVP_MD_CTX_reset(context->ctx);

    if (1 != EVP_DigestInit_ex(context->ctx, context->digestAlg, NULL))
        handleErrors();
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

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    context = malloc(sizeof(OpenSSLCipherContext));
    context->nativeBuffer = (unsigned char*)nativeBuffer;
    context->nativeBuffer2 = (unsigned char*)nativeBuffer2;
    context->ctx = ctx;

    return (jlong)(intptr_t)context;
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

     EVP_CIPHER_CTX_free(context->ctx);
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
    if (ivNative == NULL)
        return;

    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, 0));
    if (keyNative == NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        return;
    }

    if (1 != EVP_CipherInit_ex(ctx, evp_cipher1, NULL, keyNative, ivNative, mode))
        handleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

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

    if(1 != EVP_CipherUpdate(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
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

    if (1 != EVP_CipherUpdate(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen))
        handleErrors();

    if (1 != EVP_CipherFinal_ex(ctx, buf, &outputLen1))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
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
        inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (inputNative == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);
            return -1;
        }
    }

    if (first_time_gcm == 0) {
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
    if(1 != EVP_CipherInit_ex(ctx, evp_gcm_cipher, NULL, NULL, NULL, 1 )) /* 1 - Encrypt mode 0 Decrypt Mode*/
        handleErrors();

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
        handleErrors();

    if(1 != EVP_CipherInit_ex(ctx, NULL, NULL, keyNative, ivNative, -1))
        handleErrors();

    /* provide AAD */
    if(1 != EVP_CipherUpdate(ctx, NULL, &len, aadNative, aadLen))
        handleErrors();

    /* encrypt plaintext and obtain ciphertext */
    if (inLen > 0) {
        if(1 != EVP_CipherUpdate(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen))
            handleErrors();
        len_cipher = len;
    }

    /* finalize the encryption */
    if(1 != EVP_CipherFinal_ex(ctx, outputNative + outOffset + len_cipher, &len))
        handleErrors();

    /* Get the tag, place it at the end of the cipherText buffer */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, outputNative + outOffset + len + len_cipher))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);

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

    if (first_time_gcm == 0) {
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

    if(1 != EVP_CipherInit_ex(ctx, evp_gcm_cipher, NULL, NULL, NULL, 0 )) /* 1 - Encrypt mode 0 Decrypt Mode*/
        handleErrors();

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, keyNative, ivNative))
        handleErrors();

    /* Provide any AAD data */
    if (aadLen > 0) {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aadNative, aadLen))
            handleErrors();
    }

    if (inLen - tagLen > 0) {
        if(!EVP_DecryptUpdate(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen - tagLen))
            handleErrors();

        plaintext_len = len;
    }

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, inputNative + inOffset + inLen - tagLen))
        handleErrors();

    ret = EVP_DecryptFinal(ctx, outputNative + outOffset + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    if (aadLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

    if (ret > 0) {
        /* Successful Decryption */
        plaintext_len += len;
        return (jint)plaintext_len;
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
    RSA* publicRSAKey;
    BIGNUM* nBN;
    BIGNUM* eBN;
    int ret = 0;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (nNative == NULL) {
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (eNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        return -1;
    }

    publicRSAKey = RSA_new();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);

    if (publicRSAKey == NULL || nBN == NULL || eBN == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        return -1;
    }

    ret = RSA_set0_key(publicRSAKey, nBN, eBN, NULL);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);

    if (ret == 0) {
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
    unsigned char* nNative;
    unsigned char* dNative;
    unsigned char* eNative;
    unsigned char* pNative;
    unsigned char* qNative;
    unsigned char* dpNative;
    unsigned char* dqNative;
    unsigned char* qinvNative;
    RSA* privateRSACrtKey;
    BIGNUM* nBN;
    BIGNUM* eBN;
    BIGNUM* dBN;
    BIGNUM* pBN;
    BIGNUM* qBN;
    BIGNUM* dpBN;
    BIGNUM* dqBN;
    BIGNUM* qinvBN;

    int ret = 0;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (nNative == NULL) {
        return -1;
    }

    dNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, d, 0));
    if (dNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (eNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        return -1;
    }

    pNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, p, 0));
    if (pNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        return -1;
    }

    qNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, q, 0));
    if (qNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        return -1;
    }

    dpNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dp, 0));
    if (dpNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
        return -1;
    }

    dqNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dq, 0));
    if (dqNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, 0);
        return -1;
    }

    qinvNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, qinv, 0));
    if (qinvNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, 0);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, 0);
        return -1;
    }

    privateRSACrtKey = RSA_new();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);
    dBN = convertJavaBItoBN(dNative, dLen);

    if (privateRSACrtKey == NULL || nBN == NULL || eBN == NULL || dBN == NULL) {

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

    ret = RSA_set0_key(privateRSACrtKey, nBN, eBN, dBN);

    pBN = convertJavaBItoBN(pNative, pLen);
    qBN = convertJavaBItoBN(qNative, qLen);

    if (ret == 0 || pBN == NULL || qBN == NULL) {
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

    ret = RSA_set0_factors(privateRSACrtKey, pBN, qBN);

    dpBN = convertJavaBItoBN(dpNative, dpLen);
    dqBN = convertJavaBItoBN(dqNative, dqLen);
    qinvBN = convertJavaBItoBN(qinvNative, qinvLen);

    if (ret == 0 || dpBN == NULL || dqBN == NULL || qinvBN == NULL) {
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

    ret = RSA_set0_crt_params(privateRSACrtKey, dpBN, dqBN, qinvBN);

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

    return (jlong)(intptr_t)privateRSACrtKey;
}

/* Free RSA Public/Private Key
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    destroyRSAKey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_destroyRSAKey
  (JNIEnv *env, jclass obj, jlong rsaKey) {
    RSA_free((RSA*)rsaKey);
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
    RSA* rsaKey;
    int msg_len;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (kNative == NULL) {
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (mNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, 0);
        return -1;
    }

    rsaKey = (RSA*)publicRSAKey;

    // OSSL_RSA_public_decrypt returns -1 on error
    msg_len = RSA_public_decrypt(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, 0);
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

    unsigned char* kNative;
    unsigned char* mNative;
    int msg_len;
    int msg_len2;
    unsigned char* k2;
    RSA* rsaKey;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (kNative == NULL) {
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (mNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, 0);
        return -1;
    }

    rsaKey = (RSA*)privateRSAKey;

    // OSSL_RSA_private_encrypt returns -1 on error
    msg_len = RSA_private_encrypt(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    if (verify != -1 && msg_len != -1) {
        if (verify == kLen) {
            k2 = malloc(kLen * (sizeof(unsigned char)));
            if (k2 != NULL) {

                //mNative is size 'verify'
                msg_len2 = RSA_public_decrypt(verify, mNative, k2, rsaKey, RSA_NO_PADDING);
                if (msg_len2 != -1) {

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

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, 0);
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
    int c;
    int i;
    BIGNUM* bn;
    if (neg != 0) {
        // number is negative in two's complement form
        // need to extract magnitude
        c = 1;
        i = 0;
        for (i = len - 1; i >= 0; i--) {
            in[i] ^= 0xff; // flip bits
            if(c) { // add 1 for as long as needed
                c = (++in[i]) == 0;
            }
        }
    }
    bn = BN_bin2bn(in, len, NULL);
    if (bn != NULL) {
        BN_set_negative(bn, neg);
    }
    return bn;
}
