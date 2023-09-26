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
 * (c) Copyright IBM Corp. 2022, 2023 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECFieldF2m;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import jdk.crypto.jniprovider.NativeCrypto;

import sun.security.ec.point.*;
import sun.security.jca.JCAUtil;
import sun.security.provider.Sun;
import sun.security.util.ECUtil;

import static sun.security.ec.ECOperations.IntermediateValueException;
import static sun.security.util.SecurityProviderConstants.DEF_EC_KEY_SIZE;

/**
 * Native EC keypair generator.
 */
public final class NativeECKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int KEY_SIZE_MIN = 112;
    private static final int KEY_SIZE_MAX = 571;

    private static NativeCrypto nativeCrypto;
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    /* used to seed the keypair generator */
    private SecureRandom random;

    /* size of the key to generate, KEY_SIZE_MIN <= keySize <= KEY_SIZE_MAX */
    private int keySize;

    /* parameters specified via init, if any */
    private ECParameterSpec params;

    /* the type of EC curve */
    private String curve;

    /* the java implementation, initialized if needed */
    private ECKeyPairGenerator javaImplementation;

    /**
     * Constructs a new NativeECKeyPairGenerator.
     */
    public NativeECKeyPairGenerator() {
        // initialize to default in case the app does not call initialize()
        initialize(DEF_EC_KEY_SIZE, null);
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
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
            this.javaImplementation = new ECKeyPairGenerator();
            this.javaImplementation.initialize(keySize, random);
            return;
        }

        if (keySize < KEY_SIZE_MIN) {
            throw new InvalidParameterException
                ("Key size must be at least " + KEY_SIZE_MIN + " bits");
        }
        if (keySize > KEY_SIZE_MAX) {
            throw new InvalidParameterException
                ("Key size must be at most " + KEY_SIZE_MAX + " bits");
        }
        this.keySize = keySize;
        this.params = ECUtil.getECParameterSpec(null, keySize);
        if (this.params == null) {
            throw new InvalidParameterException(
                "No EC parameters available for key size " + keySize + " bits");
        }
        this.random = random;

        this.curve = NativeECUtil.getCurveName(this.params);
        if ((this.curve != null) && NativeECUtil.isCurveSupported(this.curve, this.params)) {
            this.javaImplementation = null;
        } else {
            this.javaImplementation = new ECKeyPairGenerator();
            this.javaImplementation.initialize(this.keySize, this.random);
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
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
            this.javaImplementation = new ECKeyPairGenerator();
            this.javaImplementation.initialize(params, random);
            return;
        }

        ECParameterSpec ecSpec = null;

        if (params instanceof ECParameterSpec) {
            ECParameterSpec ecParams = (ECParameterSpec) params;
            ecSpec = ECUtil.getECParameterSpec(null, ecParams);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                    "Unsupported curve: " + params);
            }
        } else if (params instanceof ECGenParameterSpec) {
            ECGenParameterSpec ecGenParams = (ECGenParameterSpec) params;
            String name = ecGenParams.getName();
            ecSpec = ECUtil.getECParameterSpec(null, name);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                    "Unknown curve name: " + name);
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "ECParameterSpec or ECGenParameterSpec required for EC");
        }

        // Not all known curves are supported by the native implementation
        ECKeyPairGenerator.ensureCurveIsSupported(ecSpec);
        this.params = ecSpec;

        this.keySize = ecSpec.getCurve().getField().getFieldSize();
        this.random = random;

        this.curve = NativeECUtil.getCurveName(this.params);
        if ((this.curve != null) && (NativeECUtil.isCurveSupported(this.curve, this.params))) {
            this.javaImplementation = null;
        } else {
            this.initializeJavaImplementation();
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (this.javaImplementation != null) {
            return this.javaImplementation.generateKeyPair();
        }

        long nativePointer = NativeECUtil.encodeGroup(this.params);

        if (nativePointer == -1) {
            NativeECUtil.putCurveIfAbsent(this.curve, Boolean.FALSE);
            if (nativeCryptTrace) {
                System.err.println("Could not encode group for curve " + this.curve
                        + " in OpenSSL, using Java crypto implementation.");
            }
            try {
                this.initializeJavaImplementation();
            } catch (InvalidAlgorithmParameterException ex) {
                throw new ProviderException(ex);
            }
            return this.javaImplementation.generateKeyPair();
        }

        int fieldType;
        ECField field = params.getCurve().getField();
        if (field instanceof ECFieldFp) {
            fieldType = NativeCrypto.ECField_Fp;
        } else if (field instanceof ECFieldF2m) {
            fieldType = NativeCrypto.ECField_F2m;
        } else {
            NativeECUtil.putCurveIfAbsent(this.curve, Boolean.FALSE);
            if (nativeCryptTrace) {
                System.err.println("Field type not supported for curve " + this.curve
                        + " by OpenSSL, using Java crypto implementation.");
            }
            try {
                this.initializeJavaImplementation();
            } catch (InvalidAlgorithmParameterException ex) {
                throw new ProviderException(ex);
            }
            return this.javaImplementation.generateKeyPair();
        }
        if (nativeCrypto == null) {
            nativeCrypto = NativeCrypto.getNativeCrypto();
        }

        int coordinatesSize = (params.getCurve().getField().getFieldSize() + 7) >> 3;
        byte[] x = new byte[coordinatesSize];
        byte[] y = new byte[coordinatesSize];
        byte[] s = new byte[coordinatesSize];

        int ret = nativeCrypto.ECGenerateKeyPair(nativePointer,
                                                 x, x.length,
                                                 y, y.length,
                                                 s, s.length,
                                                 fieldType);

        if (ret == -1) {
            NativeECUtil.putCurveIfAbsent(this.curve, Boolean.FALSE);
            if (nativeCryptTrace) {
                System.err.println("Could not generate key pair for curve " + this.curve
                        + " using OpenSSL, using Java crypto implementation for key generation.");
            }
            try {
                this.initializeJavaImplementation();
            } catch (InvalidAlgorithmParameterException ex) {
                throw new ProviderException(ex);
            }
            return this.javaImplementation.generateKeyPair();
        }

        BigInteger xBI = new BigInteger(1, x);
        BigInteger yBI = new BigInteger(1, y);
        BigInteger sBI = new BigInteger(1, s);
        ECPoint w = new ECPoint(xBI, yBI);
        PublicKey publicKey;
        PrivateKey privateKey;
        try {
            publicKey = new ECPublicKeyImpl(w, this.params);
        } catch (Exception ex) {
            throw new ProviderException("Could not generate key pair. Error with data transformation.");
        }
        try {
            privateKey = new ECPrivateKeyImpl(sBI, this.params);
        } catch (Exception ex) {
            throw new ProviderException("Could not generate key pair. Error with data transformation.");
        }

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Initializes the java implementation.
     */
    private void initializeJavaImplementation() throws InvalidAlgorithmParameterException{
        this.javaImplementation = new ECKeyPairGenerator();
        this.javaImplementation.initialize(this.params, this.random);
    }
}
