/*
 * Copyright (c) 2009, 2021, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import jdk.crypto.jniprovider.NativeCrypto;

import sun.security.action.GetPropertyAction;
import sun.security.util.NamedCurve;

/**
 * Native KeyAgreement implementation for ECDH.
 */
public final class NativeECDHKeyAgreement extends KeyAgreementSpi {

    private static final NativeCrypto nativeCrypto = NativeCrypto.getNativeCrypto();
    private static final String nativeCryptTrace = GetPropertyAction.privilegedGetProperty("jdk.nativeCryptoTrace");

    /* false if OPENSSL_NO_EC2M is defined, true otherwise */
    private static final boolean nativeGF2m = nativeCrypto.ECNativeGF2m();

    /* stores whether a curve is supported by OpenSSL (true) or not (false) */
    private static final Map<String, Boolean> curveSupported = new ConcurrentHashMap<>();

    /* private key, if initialized */
    private ECPrivateKeyImpl privateKey;

    /* public key, non-null between doPhase() & generateSecret() only */
    private ECPublicKeyImpl publicKey;

    /* the type of EC curve */
    private String curve;

    /* length of the secret to be derived */
    private int secretLen;

    /* the java implementation, initialized if needed */
    private ECDHKeyAgreement javaImplementation;

    /**
     * Constructs a new NativeECDHKeyAgreement.
     */
    public NativeECDHKeyAgreement() {
    }

    @Override
    protected void engineInit(Key key, SecureRandom random)
            throws InvalidKeyException {
        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException
                ("Key must be an instance of PrivateKey");
        }
        /* attempt to translate the key if it is not an ECKey */
        this.privateKey = (ECPrivateKeyImpl) ECKeyFactory.toECKey(key);
        this.publicKey = null;

        ECParameterSpec params = this.privateKey.getParams();
        if (params instanceof NamedCurve) {
            this.curve = ((NamedCurve) params).getName();
        } else {
            /* use the OID */
            try {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
                algParams.init(this.privateKey.getParams());
                this.curve = algParams.getParameterSpec(ECGenParameterSpec.class).getName();
            } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
                /* should not happen */
                throw new InternalError(e);
            }
        }

        if ((!nativeGF2m) && this.privateKey.isECFieldF2m()) {
            /* only print the first time a curve is used */
            if ((curveSupported.putIfAbsent("EC2m", Boolean.FALSE) == null) && (nativeCryptTrace != null)) {
                System.err.println("EC2m is not supported by OpenSSL, using Java crypto implementation.");
            }
            this.initializeJavaImplementation(key, random);
        } else if (Boolean.FALSE.equals(curveSupported.get(this.curve))) {
            this.initializeJavaImplementation(key, random);
        } else {
            this.javaImplementation = null;
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException
                        ("Parameters not supported");
        }
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (this.javaImplementation != null) {
            return this.javaImplementation.engineDoPhase(key, lastPhase);
        }
        if (this.privateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (this.publicKey != null) {
            throw new IllegalStateException("Phase already executed");
        }
        if (!lastPhase) {
            throw new IllegalStateException
                ("Only two party agreement supported, lastPhase must be true");
        }
        if (!(key instanceof PublicKey)) {
            throw new InvalidKeyException
                ("Key must be an instance of PublicKey");
        }
        /* attempt to translate the key if it is not an ECKey */
        this.publicKey = (ECPublicKeyImpl) ECKeyFactory.toECKey(key);

        ECParameterSpec params = this.publicKey.getParams();
        int keyLenBits = params.getCurve().getField().getFieldSize();
        this.secretLen = (keyLenBits + 7) >> 3;

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (this.javaImplementation != null) {
            return this.javaImplementation.engineGenerateSecret();
        }
        byte[] secret = new byte[this.secretLen];
        try {
            engineGenerateSecret(secret, 0);
        } catch (ShortBufferException e) {
            /* should not happen */
            throw new InternalError(e);
        }
        return secret;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (this.javaImplementation != null) {
            return this.javaImplementation.engineGenerateSecret(sharedSecret, offset);
        }
        if ((offset + this.secretLen) > sharedSecret.length) {
            throw new ShortBufferException("Need " + this.secretLen
                + " bytes, only " + (sharedSecret.length - offset)
                + " available");
        }
        if ((this.privateKey == null) || (this.publicKey == null)) {
            throw new IllegalStateException("Not initialized correctly");
        }
        long nativePublicKey = this.publicKey.getNativePtr();
        long nativePrivateKey = this.privateKey.getNativePtr();
        if ((nativePublicKey == -1) || (nativePrivateKey == -1)) {
            if (curveSupported.putIfAbsent(this.curve, Boolean.FALSE) != null) {
                throw new ProviderException("Could not convert keys to native format");
            }
            if (nativeCryptTrace != null) {
                System.err.println(this.curve + " is not supported by OpenSSL, using Java crypto implementation.");
            }
            try {
                this.initializeJavaImplementation(this.privateKey, null);
                this.javaImplementation.engineDoPhase(this.publicKey, true);
            } catch (InvalidKeyException e) {
                /* should not happen */
                throw new InternalError(e);
            }
            return this.javaImplementation.engineGenerateSecret(sharedSecret, offset);
        }
        if ((curveSupported.putIfAbsent(this.curve, Boolean.TRUE) == null) && (nativeCryptTrace != null)) {
            System.err.println(this.curve + " is supported by OpenSSL, using native crypto implementation.");
        }
        int ret;
        synchronized (this.privateKey) {
            ret = nativeCrypto.ECDeriveKey(nativePublicKey, nativePrivateKey, sharedSecret, offset, this.secretLen);
        }
        if (ret == -1) {
            throw new ProviderException("Could not derive key");
        }
        return this.secretLen;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException,
            InvalidKeyException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }
        if (!(algorithm.equals("TlsPremasterSecret"))) {
            throw new NoSuchAlgorithmException
                ("Only supported for algorithm TlsPremasterSecret");
        }
        return new SecretKeySpec(engineGenerateSecret(), "TlsPremasterSecret");
    }

    /**
     * Initializes the java implementation.
     *
     * @param key the private key
     * @param random source of randomness
     */
    private void initializeJavaImplementation(Key key, SecureRandom random) throws InvalidKeyException {
        this.javaImplementation = new ECDHKeyAgreement();
        this.javaImplementation.engineInit(key, random);
    }
}
