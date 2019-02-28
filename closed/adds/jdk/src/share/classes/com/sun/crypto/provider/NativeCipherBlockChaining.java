/*
 * Copyright (c) 1997, 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2019 All Rights Reserved
 * ===========================================================================
 */

package com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.ProviderException;

import java.util.ArrayDeque;
import jdk.crypto.jniprovider.NativeCrypto;

/**
 * This class represents the native implementation of ciphers in
 * cipher block chaining (CBC) mode.
 *
 * The class uses NativeCrypto class as an interface to access the
 * native implementation of CBC crypto.
 *
 */

class NativeCipherBlockChaining extends FeedbackCipher  {

    protected final static int numContexts = 4096;
    protected static long[] contexts;
    protected static ArrayDeque<Integer> avStack = new ArrayDeque<Integer>(numContexts);

    private static NativeCrypto nativeCrypto;

    /*
     * Initialize the CBC context.
     */
    static {
        nativeCrypto = NativeCrypto.getNativeCrypto();
        contexts = new long[numContexts];

        for (int i = 0; i < numContexts; i++) {
            long context = nativeCrypto.CBCCreateContext();
            if (context == -1) {
                throw new ProviderException("Error in Native CipherBlockChaining");
            }
            contexts[i] = context;
            avStack.push(i);
        }
    }


    /*
     * Get CBC context.
     */
    synchronized static long getContext(NativeCipherBlockChaining cipher) {

        if (avStack.isEmpty()) {
            cipher.ctxIndx = -1;
            long context = nativeCrypto.CBCCreateContext();
            if (context == -1) {
                throw new ProviderException("Error in Native CipherBlockChaining");
            }
            cipher.nativeContext = context;
        } else {
            cipher.ctxIndx = avStack.pop();
            cipher.nativeContext = contexts[cipher.ctxIndx];
        }

        return cipher.nativeContext;
    }

    /*
     * Release the CBC context.
     */
    synchronized static void releaseContext(NativeCipherBlockChaining cipher /*int indx*/) {

        if(cipher.ctxIndx == -1) {
            long ret = nativeCrypto.CBCDestroyContext(cipher.nativeContext);
            if (ret == -1) {
                throw new ProviderException("Error in Native CipherBlockChaining");
            }
        } else {
            avStack.push(cipher.ctxIndx);
        }
    }


    private int mode; // 0: decryption 1: encryption

    /*
     * random bytes that are initialized with iv
     */
    protected byte[] r;
    protected byte[] rSave = null;
    protected byte[] key;
    protected long nativeContext;
    protected int ctxIndx;

    /*
     * Constructor
     */
    NativeCipherBlockChaining(SymmetricCipher embeddedCipher) {
        super(embeddedCipher);
        r = new byte[blockSize];
        nativeContext = getContext(this);
    }

    /**
     * Gets the name of this feedback mode.
     *
     * @return the string <code>CBC</code>
     */
    String getFeedback() {

        return "CBC";
    }

    /**
     * Initializes the cipher in the specified mode with the given key
     * and iv.
     *
     * @param decrypting flag indicating encryption or decryption
     * @param algorithm the algorithm name
     * @param key the key
     * @param iv the iv
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     */
    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv)
            throws InvalidKeyException {

        if ((key == null) || (iv == null) || (iv.length != blockSize)) {
            throw new InvalidKeyException("Internal error");
        }

        this.iv = iv.clone();
        this.key = key.clone();
        System.arraycopy(this.iv, 0, r, 0, blockSize); // setting running state to be IV

        mode = (decrypting) ? 0 : 1;

        int ret = nativeCrypto.CBCInit(nativeContext, mode, iv, iv.length, key, key.length);
        if (ret == -1) {
            throw new ProviderException("Error in Native CipherBlockChaining");
        }

    }

    /**
     * Resets the iv to its original value.
     * This is used when doFinal is called in the Cipher class, so that the
     * cipher can be reused (with its original iv).
     */
    void reset() {
        System.arraycopy(iv, 0, r, 0, blockSize);
        int ret = nativeCrypto.CBCInit(nativeContext, mode, iv, iv.length, key, key.length);
        if (ret == -1) {
            throw new ProviderException("Error in Native CipherBlockChaining");
        }
    }

    /**
     * Save the current content of this cipher.
     */
    void save() {
        if (rSave == null) {
            rSave = new byte[blockSize];
        }
        System.arraycopy(r, 0, rSave, 0, blockSize);
    }

    /**
     * Restores the content of this cipher to the previous saved one.
     */
    void restore() {
        System.arraycopy(rSave, 0, r, 0, blockSize);
        int ret = nativeCrypto.CBCInit(nativeContext, mode, r, r.length, key, key.length);
        if (ret == -1) {
            throw new ProviderException("Error in Native CipherBlockChaining");
        }
    }

    /**
     * Performs encryption operation.
     *
     * <p>The input plain text <code>plain</code>, starting at
     * <code>plainOffset</code> and ending at
     * <code>(plainOffset + plainLen - 1)</code>, is encrypted.
     * The result is stored in <code>cipher</code>, starting at
     * <code>cipherOffset</code>.
     *
     * @param plain the buffer with the input data to be encrypted
     * @param plainOffset the offset in <code>plain</code>
     * @param plainLen the length of the input data
     * @param cipher the buffer for the result
     * @param cipherOffset the offset in <code>cipher</code>
     * @exception ProviderException if <code>len</code> is not
     * a multiple of the block size
     * @return the length of the encrypted data
     */
    int encrypt(byte[] plain, int plainOffset, int plainLen,
                byte[] cipher, int cipherOffset) {

        if (plainLen <= 0) {
            return plainLen;
        }

        if ((plainLen % blockSize) != 0) {
            throw new ProviderException("Internal error in input buffering");
        }

        int ret = nativeCrypto.CBCUpdate(nativeContext, plain, plainOffset,
                                          plainLen, cipher, cipherOffset);
        if (ret == -1) {
            throw new ProviderException("Error in Native CipherBlockChaining");
        }

        // saving current running state
        System.arraycopy(cipher, cipherOffset+plainLen-blockSize, r, 0, blockSize);
        return ret;
    }

    /**
     * Performs decryption operation.
     *
     * <p>The input cipher text <code>cipher</code>, starting at
     * <code>cipherOffset</code> and ending at
     * <code>(cipherOffset + cipherLen - 1)</code>, is decrypted.
     * The result is stored in <code>plain</code>, starting at
     * <code>plainOffset</code>.
     *
     * <p>It is also the application's responsibility to make sure that
     * <code>init</code> has been called before this method is called.
     * (This check is omitted here, to avoid double checking.)
     *
     * @param cipher the buffer with the input data to be decrypted
     * @param cipherOffset the offset in <code>cipherOffset</code>
     * @param cipherLen the length of the input data
     * @param plain the buffer for the result
     * @param plainOffset the offset in <code>plain</code>
     * @exception ProviderException if <code>len</code> is not
     * a multiple of the block size
     * @return the length of the decrypted data
     */
    int decrypt(byte[] cipher, int cipherOffset, int cipherLen,
                byte[] plain, int plainOffset) {

        return encrypt(cipher, cipherOffset, cipherLen,
                       plain, plainOffset);
    }


    /**
     * Performs last encryption operation.
     *
     * <p>The input plain text <code>plain</code>, starting at
     * <code>plainOffset</code> and ending at
     * <code>(plainOffset + plainLen - 1)</code>, is encrypted.
     * The result is stored in <code>cipher</code>, starting at
     * <code>cipherOffset</code>.
     *
     * @param plain the buffer with the input data to be encrypted
     * @param plainOffset the offset in <code>plain</code>
     * @param plainLen the length of the input data
     * @param cipher the buffer for the result
     * @param cipherOffset the offset in <code>cipher</code>
     * @return the length of the encrypted data
     */
    int encryptFinal(byte[] plain, int plainOffset, int plainLen,
                     byte[] cipher, int cipherOffset) {

        int ret = -1;

        if(plain == cipher) {
            ret = nativeCrypto.CBCFinalEncrypt(nativeContext, plain.clone(),
                                               plainOffset, plainLen, cipher, cipherOffset);
        } else {
            ret = nativeCrypto.CBCFinalEncrypt(nativeContext, plain, plainOffset,
                                                plainLen, cipher, cipherOffset);
        }

        if (ret == -1) {
            throw new ProviderException("Error in Native CipherBlockChaining");
        }

        return ret;
    }

    /*
     * Finalize method to release the CBC contexts.
     */
    @Override
    public void finalize() {

        releaseContext(this);
    }
}
