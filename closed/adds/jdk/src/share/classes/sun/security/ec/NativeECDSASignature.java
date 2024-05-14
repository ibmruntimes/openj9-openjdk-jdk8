/*
 * Copyright (c) 2009, 2020, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2024, 2024 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Optional;

import jdk.crypto.jniprovider.NativeCrypto;
import sun.security.provider.Sun;
import sun.security.util.ECUtil;

/**
 * ECDSA signature implementation. This class currently supports the
 * following algorithm names:
 *
 * <ul>
 *   <li>"NONEwithECDSA"</li>
 *   <li>"SHA1withECDSA"</li>
 *   <li>"SHA224withECDSA"</li>
 *   <li>"SHA256withECDSA"</li>
 *   <li>"SHA384withECDSA"</li>
 *   <li>"SHA512withECDSA"</li>
 * </ul>
 *
 * @since   1.7
 */
abstract class NativeECDSASignature extends SignatureSpi {

    private static NativeCrypto nativeCrypto;
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    // message digest implementation we use
    private final MessageDigest messageDigest;

    // supplied entropy
    private SecureRandom random;

    // flag indicating whether the digest has been reset
    private boolean needsReset;

    // private key, if initialized for signing
    private ECPrivateKey privateKey;

    // native private key pointer, if initialized for signing
    private long nativePrivateKey;

    // public key, if initialized for verifying
    private ECPublicKey publicKey;

    // native public key pointer, if initialized for verifying
    private long nativePublicKey;

    // signature parameters
    private ECParameterSpec sigParams;

    // the Java implementation, if needed
    ECDSASignature javaImplementation;

    /**
     * Constructs a new NativeECDSASignature.
     *
     * @exception ProviderException if the native ECC library is unavailable.
     */
    NativeECDSASignature() {
        messageDigest = null;
    }

    /**
     * Constructs a new NativeECDSASignature. Used by subclasses.
     */
    NativeECDSASignature(String digestName) {
        try {
            messageDigest = MessageDigest.getInstance(digestName);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
        needsReset = false;
    }

    // Nested class for NONEwithECDSA signatures.
    public static final class Raw extends NativeECDSASignature {

        // the longest supported digest is 512 bits (SHA-512)
        private static final int RAW_ECDSA_MAX = 64;

        private final byte[] precomputedDigest;
        private int offset;

        public Raw() {
            precomputedDigest = new byte[RAW_ECDSA_MAX];
        }

        // Stores the precomputed message digest value.
        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            if (this.javaImplementation != null) {
                this.javaImplementation.engineUpdate(b);
            } else {
                if (offset >= precomputedDigest.length) {
                    offset = RAW_ECDSA_MAX + 1;
                    return;
                }
                precomputedDigest[offset++] = b;
            }
        }

        // Stores the precomputed message digest value.
        @Override
        protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {
            if (this.javaImplementation != null) {
                this.javaImplementation.engineUpdate(b, off, len);
            } else {
                if (offset >= precomputedDigest.length) {
                    offset = RAW_ECDSA_MAX + 1;
                    return;
                }
                System.arraycopy(b, off, precomputedDigest, offset, len);
                offset += len;
            }
        }

        // Stores the precomputed message digest value.
        @Override
        protected void engineUpdate(ByteBuffer byteBuffer) {
            if (this.javaImplementation != null) {
                this.javaImplementation.engineUpdate(byteBuffer);
            } else {
                int len = byteBuffer.remaining();
                if (len <= 0) {
                    return;
                }
                if (len >= (precomputedDigest.length - offset)) {
                    offset = RAW_ECDSA_MAX + 1;
                    return;
                }
                byteBuffer.get(precomputedDigest, offset, len);
                offset += len;
            }
        }

        @Override
        void resetDigest() {
            offset = 0;
        }

        // Returns the precomputed message digest value.
        @Override
        byte[] getDigestValue() throws SignatureException {
            if (offset > RAW_ECDSA_MAX) {
                throw new SignatureException("Message digest is too long");
            }
            byte[] result = new byte[offset];
            System.arraycopy(precomputedDigest, 0, result, 0, offset);
            offset = 0;

            return result;
        }
    }

    // Nested class for SHA1withECDSA signatures.
    public static final class SHA1 extends NativeECDSASignature {
        public SHA1() {
            super("SHA1");
        }
    }

    // Nested class for SHA224withECDSA signatures.
    public static final class SHA224 extends NativeECDSASignature {
        public SHA224() {
            super("SHA-224");
        }
    }

    // Nested class for SHA256withECDSA signatures.
    public static final class SHA256 extends NativeECDSASignature {
        public SHA256() {
            super("SHA-256");
        }
    }

    // Nested class for SHA384withECDSA signatures.
    public static final class SHA384 extends NativeECDSASignature {
        public SHA384() {
            super("SHA-384");
        }
    }

    // Nested class for SHA512withECDSA signatures.
    public static final class SHA512 extends NativeECDSASignature {
        public SHA512() {
            super("SHA-512");
        }
    }

    // Initialize for verification. See JCA doc.
    @Override
    protected void engineInitVerify(PublicKey publicKey)
    throws InvalidKeyException {
        ECPublicKey key = (ECPublicKey) ECKeyFactory.toECKey(publicKey);
        if (!isCompatible(this.sigParams, key.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        }

        // Should check that the supplied key is appropriate for signature
        // algorithm (e.g. P-256 for SHA256withECDSA).
        this.publicKey = key;
        this.privateKey = null;
        resetDigest();

        this.nativePublicKey = NativeECUtil.getPublicKeyNativePtr(key);
        if (this.nativePublicKey == -1) {
            this.javaImplementation = getJavaInstance();
            this.javaImplementation.engineInitVerify(publicKey);
            if (nativeCryptTrace) {
                System.err.println("InitVerify: Could not create a pointer to a native key."
                        + " Using Java implementation.");
            }
            return;
        }
        this.javaImplementation = null;
        if (nativeCryptTrace) {
            System.err.println("InitVerify: Keys were successfully converted to native OpenSSL format.");
        }
    }

    // Initialize for signing. See JCA doc.
    @Override
    protected void engineInitSign(PrivateKey privateKey)
    throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    // Initialize for signing. See JCA doc.
    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
    throws InvalidKeyException {
        if (random == null) {
            if (nativeCryptTrace) {
                System.err.println("No SecureRandom implementation was provided during"
                        + " initialization. Using OpenSSL.");
            }
        } else if ((random.getProvider() instanceof Sun)
            && ("NativePRNG".equals(random.getAlgorithm()) || "DRBG".equals(random.getAlgorithm()))
        ) {
            if (nativeCryptTrace) {
                System.err.println("Default SecureRandom implementation was provided during"
                        + " initialization. Using OpenSSL.");
            }
        } else {
            if (nativeCryptTrace) {
                System.err.println("SecureRandom implementation was provided during"
                        + " initialization. Using Java implementation instead of OpenSSL.");
            }
            this.javaImplementation = getJavaInstance();
            this.javaImplementation.engineInitSign(privateKey, random);
            return;
        }

        ECPrivateKey key = (ECPrivateKey) ECKeyFactory.toECKey(privateKey);
        if (!isCompatible(this.sigParams, key.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        }

        // Should check that the supplied key is appropriate for signature
        // algorithm (e.g. P-256 for SHA256withECDSA).
        this.privateKey = key;
        this.publicKey = null;
        this.random = random;
        resetDigest();

        this.nativePrivateKey = NativeECUtil.getPrivateKeyNativePtr(key);
        if (this.nativePrivateKey == -1) {
            this.javaImplementation = getJavaInstance();
            this.javaImplementation.engineInitSign(privateKey, random);
            if (nativeCryptTrace) {
                System.err.println("InitSign: Could not create a pointer to a native key."
                        + " Using Java implementation.");
            }
            return;
        }
        this.javaImplementation = null;
        if (nativeCryptTrace) {
            System.err.println("InitSign: Keys were successfully converted to native OpenSSL format.");
        }
    }

    /**
     * Resets the message digest if needed.
     */
    void resetDigest() {
        if (needsReset) {
            if (messageDigest != null) {
                messageDigest.reset();
            }
            needsReset = false;
        }
    }

    /**
     * Returns the message digest value.
     */
    byte[] getDigestValue() throws SignatureException {
        needsReset = false;
        return messageDigest.digest();
    }

    // Update the signature with the plaintext data. See JCA doc.
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (this.javaImplementation != null) {
            this.javaImplementation.engineUpdate(b);
        } else {
            messageDigest.update(b);
            needsReset = true;
        }
    }

    // Update the signature with the plaintext data. See JCA doc.
    @Override
    protected void engineUpdate(byte[] b, int off, int len)
    throws SignatureException {
        if (this.javaImplementation != null) {
            this.javaImplementation.engineUpdate(b, off, len);
        } else {
            messageDigest.update(b, off, len);
            needsReset = true;
        }
    }

    // Update the signature with the plaintext data. See JCA doc.
    @Override
    protected void engineUpdate(ByteBuffer byteBuffer) {
        if (this.javaImplementation != null) {
            this.javaImplementation.engineUpdate(byteBuffer);
        } else {
            int len = byteBuffer.remaining();
            if (len <= 0) {
                return;
            }

            messageDigest.update(byteBuffer);
            needsReset = true;
        }
    }

    private static boolean isCompatible(ECParameterSpec sigParams,
            ECParameterSpec keyParams) {
        if (sigParams == null) {
            // no restriction on key param
            return true;
        }
        return ECUtil.equals(sigParams, keyParams);
    }

    // Sign the data and return the signature. See JCA doc.
    @Override
    protected byte[] engineSign() throws SignatureException {
        if (this.javaImplementation != null) {
            return this.javaImplementation.engineSign();
        }

        byte[] digest = getDigestValue();
        int digestLen = digest.length;
        ECParameterSpec params = privateKey.getParams();
        int sigLen = ((params.getOrder().bitLength() + 7) / 8) * 2;
        byte[] sig = new byte[sigLen];

        if (nativeCrypto == null) {
            nativeCrypto = NativeCrypto.getNativeCrypto();
        }

        int ret;
        synchronized (this.privateKey) {
            ret = nativeCrypto.ECDSASign(nativePrivateKey, digest, digestLen, sig, sig.length);
        }
        if (ret == -1) {
            throw new ProviderException("An error occured when creating signature");
        }

        if (nativeCryptTrace) {
            System.err.println("Sign: Signature was successfully created.");
        }

        return ECUtil.encodeSignature(sig);
    }

    // Verify the data and return the result. See JCA doc.
    @Override
    protected boolean engineVerify(byte[] signature) throws SignatureException {
        if (this.javaImplementation != null) {
            return this.javaImplementation.engineVerify(signature);
        }

        if (nativeCrypto == null) {
            nativeCrypto = NativeCrypto.getNativeCrypto();
        }

        byte[] sig = ECUtil.decodeSignature(signature);
        byte[] digest = getDigestValue();
        int digestLen = digest.length;

        int ret;
        synchronized (this.publicKey) {
            ret = nativeCrypto.ECDSAVerify(nativePublicKey, digest, digestLen, sig, sig.length);
        }

        if (ret == 1) {
            if (nativeCryptTrace) {
                System.err.println("Verify: Signature was successfully verified.");
            }
            return true;
        } else if (ret == 0) {
            if (nativeCryptTrace) {
                System.err.println("Verify: Signature verification was unsuccessful.");
            }
            return false;
        } else {
            throw new ProviderException("An error occured when verifying signature");
        }
    }

    // Set parameter, not supported. See JCA doc.
    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value)
    throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
    throws InvalidAlgorithmParameterException {
        if (params == null) {
            sigParams = null;
            return;
        }
        if (!(params instanceof ECParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "Parameters must be of type ECParameterSpec");
        }
        ECKey key = (this.privateKey == null) ? this.publicKey : this.privateKey;
        if ((key != null) && !isCompatible((ECParameterSpec) params, key.getParams())) {
            throw new InvalidAlgorithmParameterException
                ("Signature params does not match key params");
        }
        sigParams = (ECParameterSpec) params;
    }

    // Get parameter, not supported. See JCA doc.
    @Deprecated
    @Override
    protected Object engineGetParameter(String param)
    throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (sigParams == null) {
            return null;
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(sigParams);
            return ap;
        } catch (Exception e) {
            // Should never happen.
            throw new ProviderException("Error retrieving EC parameters", e);
        }
    }

    private ECDSASignature getJavaInstance() {
        if (this.messageDigest == null) {
            return new ECDSASignature.Raw();
        } else {
            String mdAlgo = messageDigest.getAlgorithm();
            switch (mdAlgo) {
                case "SHA1":
                    return new ECDSASignature.SHA1();
                case "SHA-224":
                    return new ECDSASignature.SHA224();
                case "SHA-256":
                    return new ECDSASignature.SHA256();
                case "SHA-384":
                    return new ECDSASignature.SHA384();
                case "SHA-512":
                    return new ECDSASignature.SHA512();
                default:
                    throw new ProviderException("Unexpected algorithm: " + mdAlgo);
            }
        }
    }
}
