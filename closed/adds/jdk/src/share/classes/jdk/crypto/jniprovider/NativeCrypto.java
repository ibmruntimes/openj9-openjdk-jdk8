/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2024 All Rights Reserved
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

import com.ibm.oti.vm.VM;

import sun.misc.Cleaner;
import sun.misc.Unsafe;
import sun.reflect.Reflection;
import sun.reflect.CallerSensitive;

import sun.security.action.GetPropertyAction;

public class NativeCrypto {

    /* Define constants for the native digest algorithm indices. */
    public static final int SHA1_160 = 0;
    public static final int SHA2_224 = 1;
    public static final int SHA2_256 = 2;
    public static final int SHA5_384 = 3;
    public static final int SHA5_512 = 4;
    public static final int MD5 = 5;

    /* Define constants for the EC field types. */
    public static final int ECField_Fp = 0;
    public static final int ECField_F2m = 1;

    public static final long OPENSSL_VERSION_1_0_0 = 0x1_00_00_000L;
    public static final long OPENSSL_VERSION_1_1_0 = 0x1_01_00_000L;
    public static final long OPENSSL_VERSION_1_1_1 = 0x1_01_01_000L;
    public static final long OPENSSL_VERSION_3_0_0 = 0x3_00_00_000L;

    private static final boolean useNativeCrypto = Boolean.parseBoolean(
            GetPropertyAction.privilegedGetProperty("jdk.nativeCrypto", "true"));

    private static final boolean traceEnabled = Boolean.parseBoolean(
            GetPropertyAction.privilegedGetProperty("jdk.nativeCryptoTrace", "false"));

    //ossl_ver will be either:
    // -1 : library load failed
    // or one of the OPENSSL_VERSION_x_x_x constants
    private static final long ossl_ver = AccessController.doPrivileged(
            (PrivilegedAction<Long>) () -> {
            long osslVersion;
            try {
                System.loadLibrary("jncrypto"); // check for native library
                // load OpenSSL crypto library dynamically.
                osslVersion = loadCrypto(traceEnabled);
                if (traceEnabled && (osslVersion != -1)) {
                    System.err.println("Native crypto library load succeeded - using native crypto library.");
                }
            } catch (UnsatisfiedLinkError usle) {
                if (traceEnabled) {
                    System.err.println("UnsatisfiedLinkError: Failure attempting to load jncrypto JNI library");
                    System.err.println("Warning: Native crypto library load failed." +
                            " Using Java crypto implementation.");
                }
                 // signal load failure
                osslVersion = -1;
            }

            return osslVersion;
        }).longValue();

    private static final boolean isOpenSSLFIPS = (ossl_ver != -1) && isOpenSSLFIPS();

    /**
     * Return the OpenSSL version. It will return -1 if the library isn't
     * successfully loaded.
     *
     * @return the OpenSSL library version or -1, if not loaded.
     */
    public static final long getVersion() {
        return ossl_ver;
    }

    public static final boolean isLoaded() {
        return getVersion() >= 0;
    }

    /**
     * Check whether native crypto is enabled. Note that, by default, native
     * crypto is enabled (the native crypto library implementation is used).
     *
     * The property 'jdk.nativeCrypto' is used to control enablement of all
     * native cryptos (Digest, CBC, GCM, RSA, EC, and PBE), while
     * the given property should be used to control enablement of the given
     * native crypto algorithm.
     *
     * @param property the property used to control enablement of the given
     *                 algorithm
     * @param name the name of the class or the algorithm
     * @return whether the given native crypto algorithm is enabled
     */
    public static final boolean isAlgorithmEnabled(String property, String name) {
        return isAlgorithmEnabled(property, name, true, null);
    }

    /**
     * Check whether native crypto is enabled. Note that, by default, native
     * crypto is enabled (the native crypto library implementation is used).
     *
     * The property 'jdk.nativeCrypto' is used to control enablement of all
     * native cryptos (Digest, CBC, GCM, RSA, EC, and PBE), while
     * the given property should be used to control enablement of the given
     * native crypto algorithm.
     *
     * This method is used for native cryptos that have additional requirements
     * in order to load.
     *
     * @param property the property used to control enablement of the given
     *                 algorithm
     * @param name the name of the class or the algorithm
     * @param satisfied whether the additional requirements are met
     * @param explanation explanation if the native crypto is not loaded
     *                    due to the additional requirements not being met
     * @return whether the given native crypto algorithm is enabled
     */
    public static final boolean isAlgorithmEnabled(String property, String name, boolean satisfied, String explanation) {
        boolean useNativeAlgorithm = false;
        if (useNativeCrypto) {
            useNativeAlgorithm = Boolean.parseBoolean(
                    GetPropertyAction.privilegedGetProperty(property, "true"));
        }
        if (useNativeAlgorithm) {
            /*
             * User wants to use the native crypto implementation. Ensure that the
             * native crypto library is loaded successfully. Otherwise, issue a warning
             * message and fall back to the built-in java crypto implementation.
             */
            if (isLoaded()) {
                if (satisfied) {
                    if (traceEnabled) {
                        System.err.println(name + " - using native crypto library.");
                    }
                } else {
                    useNativeAlgorithm = false;
                    if (traceEnabled) {
                        System.err.println("Warning: " + name + " native requirements not satisfied. " +
                                explanation + " Using Java crypto implementation.");
                    }
                }
            } else {
                useNativeAlgorithm = false;
                if (traceEnabled) {
                    System.err.println("Warning: Native crypto library load failed." +
                            " Using Java crypto implementation.");
                }
            }
        } else {
            if (traceEnabled) {
                System.err.println(name + " native crypto implementation disabled." +
                        " Using Java crypto implementation.");
            }
        }
        return useNativeAlgorithm;
    }

    public static final boolean isEnabled() {
        return useNativeCrypto;
    }

    public static final boolean isTraceEnabled() {
        return traceEnabled;
    }

    private NativeCrypto() {
        //empty
    }

    /**
     * Check whether a native implementation is available in the loaded OpenSSL library.
     * Note that, an algorithm could be unavailable due to options used to build the
     * OpenSSL version utilized, or using a FIPS version that doesn't allow it.
     *
     * @param algorithm the algorithm checked
     * @return whether a native implementation of the given crypto algorithm is available
     */
    public static final boolean isAlgorithmAvailable(String algorithm) {
        boolean isAlgorithmAvailable = false;
        if (isLoaded()) {
            if (isOpenSSLFIPS) {
                switch (algorithm) {
                case "MD5":
                    // not available
                    break;
                default:
                    isAlgorithmAvailable = true;
                    break;
                }
            } else {
                switch (algorithm) {
                case "MD5":
                    isAlgorithmAvailable = isMD5Available();
                    break;
                default:
                    isAlgorithmAvailable = true;
                    break;
                }
            }
        }

        // Issue a message indicating whether the crypto implementation is available.
        if (traceEnabled) {
            if (isAlgorithmAvailable) {
                System.err.println(algorithm + " native crypto implementation is available.");
            } else {
                System.err.println(algorithm + " native crypto implementation is not available.");
            }
        }
        return isAlgorithmAvailable;
    }

    @CallerSensitive
    public static NativeCrypto getNativeCrypto() {

        ClassLoader callerClassLoader = Reflection.getCallerClass().getClassLoader();

        if ((callerClassLoader != null) && (callerClassLoader != VM.getVMLangAccess().getExtClassLoader())) {
            throw new SecurityException("NativeCrypto");
        }
        return new NativeCrypto();
    }

    public void createECKeyCleaner(Object owner, long key) {
        Cleaner.create(owner, new Runnable() {
            @Override
            public void run() {
                NativeCrypto.this.ECDestroyKey(key);
            }
        });
    }

    /* Native digest interfaces */

    private static final native long loadCrypto(boolean trace);

    public static final native boolean isMD5Available();

    private static final native boolean isOpenSSLFIPS();

    public final native long DigestCreateContext(long nativeBuffer,
                                                 int algoIndex);

    public final native int DigestDestroyContext(long context);

    public final native int DigestUpdate(long context,
                                         byte[] message,
                                         int messageOffset,
                                         int messageLen);

    public final native int DigestComputeAndReset(long context,
                                                  byte[] message,
                                                  int messageOffset,
                                                  int messageLen,
                                                  byte[] digest,
                                                  int digestOffset,
                                                  int digestLen);

    public final native int DigestReset(long context);

    /* Native interfaces shared by CBC and GCM. */

    public final native long CreateContext();

    public final native int DestroyContext(long context);

    public final native int CBCInit(long context,
                                    int mode,
                                    byte[] iv,
                                    int ivlen,
                                    byte[] key,
                                    int keylen,
                                    boolean doReset);

    public final native int CBCUpdate(long context,
                                      byte[] input,
                                      int inputOffset,
                                      int inputLen,
                                      byte[] output,
                                      int outputOffset);

    public final native int CBCFinalEncrypt(long context,
                                            byte[] input,
                                            int inputOffset,
                                            int inputLen,
                                            byte[] output,
                                            int outputOffset);

    /* Native GCM interfaces */

    public final native int GCMEncrypt(long context,
                                       byte[] key,
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
                                       int tagLen,
                                       boolean newIVLen,
                                       boolean newKeyLen);

    public final native int GCMDecrypt(long context,
                                       byte[] key,
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
                                       int tagLen,
                                       boolean newIVLen,
                                       boolean newKeyLen);

    /* Native RSA interfaces */
    public final native long createRSAPublicKey(byte[] n,
                                                int nLen,
                                                byte[] e,
                                                int eLen);

    public final native long createRSAPrivateCrtKey(byte[] n,
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

    public final native void destroyRSAKey(long key);

    public final native int RSADP(byte[] k,
                                  int kLen,
                                  byte[] m,
                                  int verify,
                                  long RSAPrivateCrtKey);

    public final native int RSAEP(byte[] k,
                                  int kLen,
                                  byte[] m,
                                  long RSAPublicKey);

    /* Native EC interfaces */
    public final native int ECGenerateKeyPair(long key,
                                              byte[] x,
                                              int xLen,
                                              byte[] y,
                                              int yLen,
                                              byte[] s,
                                              int sLen,
                                              int fieldType);

    public final native int ECCreatePublicKey(long key,
                                              byte[] x,
                                              int xLen,
                                              byte[] y,
                                              int yLen,
                                              int field);

    public final native int ECCreatePrivateKey(long key,
                                               byte[] s,
                                               int sLen);

    public final native long ECEncodeGF(int fieldType,
                                        byte[] a,
                                        int aLen,
                                        byte[] b,
                                        int bLen,
                                        byte[] p,
                                        int pLen,
                                        byte[] x,
                                        int xLen,
                                        byte[] y,
                                        int yLen,
                                        byte[] n,
                                        int nLen,
                                        byte[] h,
                                        int hLen);

    public final native int ECDestroyKey(long key);

    public final native int ECDeriveKey(long publicKey,
                                        long privateKey,
                                        byte[] secret,
                                        int secretOffset,
                                        int secretLen);

    public final native boolean ECNativeGF2m();

    public final native int PBEDerive(byte[] password,
                                      int passwordLength,
                                      byte[] salt,
                                      int saltLength,
                                      byte[] key,
                                      int iterations,
                                      int n,
                                      int id,
                                      int hashAlgorithm);

    /* Native ECDSA interfaces. */
    public final native int ECDSASign(long key,
                                      byte[] digest,
                                      int digestLen,
                                      byte[] signature,
                                      int sigLen);

    public final native int ECDSAVerify(long key,
                                        byte[] digest,
                                        int digestLen,
                                        byte[] signature,
                                        int sigLen);
}
