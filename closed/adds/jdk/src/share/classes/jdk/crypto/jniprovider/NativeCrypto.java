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

package jdk.crypto.jniprovider;

import java.security.*;

public class NativeCrypto {

    private static boolean loaded = false;

    static {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                try {
                    System.loadLibrary("jncrypto"); // check for native library

                    // load OpenSSL crypto library dynamically.
                    if (loadCrypto() == 0) { 
                        loaded = true;
                    } else {
                        loaded = false;
                    }
                } catch (UnsatisfiedLinkError usle) {
                    loaded = false;
                    usle.printStackTrace();
                }
                return null;
            }
        });

    }

    public static final boolean isLoaded() {
        return loaded;
    }

    /* Native digest interfaces */
    public static final native int loadCrypto();

    public static final native long DigestCreateContext(long nativeBuffer,
                                                        int algoIndex);

    public static final native int DigestUpdate(long context,
                                                byte[] message,
                                                int messageOffset,
                                                int messageLen);

    public static final native int DigestComputeAndReset(long context,
                                                         byte[] message,
                                                         int messageOffset,
                                                         int messageLen,
                                                         byte[] digest,
                                                         int digestOffset,
                                                         int digestLen);

    /* Native CBC interfaces */
    public static final native long CBCCreateContext(long nativeBuffer,
                                                     long nativeBuffer2);

    public static final native long CBCDestroyContext(long context);

    public static final native void CBCInit(long context,
                                            int mode,
                                            byte[] iv,
                                            int ivlen,
                                            byte[] key,
                                            int keylen);

    public static final native int  CBCUpdate(long context,
                                              byte[] input,
                                              int inputOffset,
                                              int inputLen,
                                              byte[] output,
                                              int outputOffset);

    public static final native int  CBCFinalEncrypt(long context,
                                               byte[] input,
                                               int inputOffset,
                                               int inputLen,
                                               byte[] output,
                                               int outputOffset);

    /* Native GCM interfaces */
    public static final native int GCMEncrypt(byte[] key,
                                              int keylen,
                                              byte[] iv,
                                              int ivlen,
                                              byte[] input,
                                              int inOffset,
                                              int inLen,
                                              byte[] output,
                                              int outOffset,
                                              byte[] aad,
                                              int aadLen,
                                              int tagLen);

    public static final native int GCMDecrypt(byte[] key,
                                              int keylen,
                                              byte[] iv,
                                              int ivlen,
                                              byte[] input,
                                              int inOffset,
                                              int inLen,
                                              byte[] output,
                                              int outOffset,
                                              byte[] aad,
                                              int aadLen,
                                              int tagLen);

    /* Native RSA interfaces */
    public static final native long createRSAPublicKey(byte[] n,
                                                       int nLen,
                                                       byte[] e,
                                                       int eLen);

    public static final native long createRSAPrivateCrtKey(byte[] n,
                                                           int nLen,
                                                           byte[] d,
                                                           int dLen,
                                                           byte[] e,
                                                           int eLen,
                                                           byte[] p,
                                                           int pLen,
                                                           byte[] q,
                                                           int qLen,
                                                           byte[] dp,
                                                           int dpLen,
                                                           byte[] dq,
                                                           int dqLen,
                                                           byte[] qinv,
                                                           int qinvLen);

    public static final native void destroyRSAKey(long key);

    public static final native int RSADP(byte[] k,
                                         int kLen,
                                         byte[] m,
                                         int verify,
                                         long RSAPrivateCrtKey);
    
    public static final native int RSAEP(byte[] k,
                                         int kLen,
                                         byte[] m,
                                         long RSAPublicKey);
}
