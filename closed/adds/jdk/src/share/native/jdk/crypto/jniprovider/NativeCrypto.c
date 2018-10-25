/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2018 All Rights Reserved
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
        EVP_MD_CTX_copy_ex(ctx,contextToCopy);
    }


    return (long)context;
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
        jboolean isCopy;
        unsigned char* messageNative = (*env)->GetPrimitiveArrayCritical(env, message, &isCopy);
        messageNative = messageNative + messageOffset;

        if (1 != EVP_DigestUpdate(context->ctx, messageNative, messageLen))
            handleErrors();

        (*env)->ReleasePrimitiveArrayCritical(env, message,  NULL, 0);
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
    jboolean isCopy;
    unsigned char* messageNative;
    unsigned char* digestNative;

    if (message != NULL) {
       messageNative = (*env)->GetPrimitiveArrayCritical(env, message, &isCopy);
       messageNative = messageNative + messageOffset;
       if (1 != EVP_DigestUpdate(context->ctx, messageNative, messageLen)) handleErrors();
           (*env)->ReleasePrimitiveArrayCritical(env, message, NULL, 0);
    }

    digestNative = (*env)->GetPrimitiveArrayCritical(env, digest , &isCopy);
    digestNative = digestNative + digestOffset;

    if (1 != EVP_DigestFinal_ex(context->ctx, digestNative, &size))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, digest,  NULL, 0);

    EVP_MD_CTX_reset(context->ctx);

    if (1 != EVP_DigestInit_ex(context->ctx, context->digestAlg, NULL))
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

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    context = malloc(sizeof(OpenSSLCipherContext));
    context->nativeBuffer  = (unsigned char*)nativeBuffer;
    context->nativeBuffer2 = (unsigned char*)nativeBuffer2;
    context->ctx = ctx;

    return (long)context;
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
    jboolean isCopy;
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

    ivNative  = (unsigned char*)((*env)->GetByteArrayElements(env, iv,  &isCopy));
    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, &isCopy));

    if (1 != EVP_CipherInit_ex(ctx, evp_cipher1, NULL, keyNative, ivNative, mode))
        handleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    (*env)->ReleaseByteArrayElements(env, iv,  ivNative,  JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, keyNative, JNI_ABORT);
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

    jboolean isCopy;
    unsigned char* inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input , &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, &isCopy));

    inputNative = inputNative + inputOffset;
    outputNative = outputNative + outputOffset;

    if(1 != EVP_CipherUpdate(ctx, outputNative, &outputLen, inputNative, inputLen))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input , NULL, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, NULL, 0);

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

    jboolean isCopy;
    unsigned char* inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input , &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, &isCopy));

    inputNative    = inputNative  + inputOffset;
    outputNative   = outputNative + outputOffset;

    if (1 != EVP_CipherUpdate(ctx, outputNative, &outputLen, inputNative, inputLen))
        handleErrors();

    if (1 != EVP_CipherFinal_ex(ctx, buf, &outputLen1))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input , NULL, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, NULL, 0);

    return outputLen+outputLen1;
}

const EVP_CIPHER* evp_gcm_cipher;
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

    jboolean isCopy;
    unsigned char* inputNative;
    int len, len_cipher = 0;
    unsigned char* keyNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key,   &isCopy));
    unsigned char* ivNative     = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,    &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output,&isCopy));
    unsigned char* aadNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad,   &isCopy));

    EVP_CIPHER_CTX* ctx = NULL;
    if (inLen > 0) {
        inputNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, &isCopy));
    }

    if (first_time_gcm == 0) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        first_time_gcm = 1;

        evp_gcm_cipher = EVP_aes_128_gcm();
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

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative,   0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative,    0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative,0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative,  0);
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

    jboolean isCopy;
    unsigned char* inputNative;
    unsigned char* aadNative;
    int ret, len, plaintext_len = 0;
    unsigned char* keyNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key,   &isCopy));
    unsigned char* ivNative     = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,    &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output,&isCopy));

    EVP_CIPHER_CTX* ctx = NULL;

    if (inLen > 0) {
        inputNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, &isCopy));
    }

    if (aadLen > 0) {
        aadNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad,   &isCopy));
    }

    if (first_time_gcm == 0) {
        //printf("Initializing OpenSSL GCM algorithm-1\n");
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        first_time_gcm = 1;
        evp_gcm_cipher = EVP_aes_128_gcm();
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
