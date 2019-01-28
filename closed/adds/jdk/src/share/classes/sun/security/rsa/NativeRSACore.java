/*
 * Copyright (c) 2003, 2015, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.rsa;

import java.math.BigInteger;
import java.util.*;

import java.security.SecureRandom;
import java.security.interfaces.*;

import javax.crypto.BadPaddingException;
import sun.security.action.GetPropertyAction;
import jdk.crypto.jniprovider.NativeCrypto;

import sun.security.jca.JCAUtil;

/**
 * Core of the RSA implementation. Has code to perform public and private key
 * RSA operations (with and without CRT for private key ops). Private CRT ops
 * also support blinding to twart timing attacks.
 *
 * The code in this class only does the core RSA operation. Padding and
 * unpadding must be done externally.
 *
 * Note: RSA keys should be at least 512 bits long
 *
 * @since   1.5
 * @author  Andreas Sterbenz
 */
public final class NativeRSACore {

    private static NativeCrypto nativeCrypto;

    static {
        nativeCrypto = NativeCrypto.getNativeCrypto();
    }

    /**
     * Return the number of bytes required to store the magnitude byte[] of
     * this BigInteger. Do not count a 0x00 byte toByteArray() would
     * prefix for 2's complement form.
     */
    public static int getByteLength(BigInteger b) {
        int n = b.bitLength();
        return (n + 7) >> 3;
    }

    /**
     * Perform an RSA public key operation.
     */
    public static byte[] rsa(byte[] msg, sun.security.rsa.RSAPublicKeyImpl key)
        throws BadPaddingException {
        return crypt_Native(msg, key);
    }

    /**
     * Perform an RSA private key operation. Uses CRT if the key is a
     * CRT key. Set 'verify' to true if this function is used for
     * generating a signature.
     */
    public static byte[] rsa(byte[] msg,sun.security.rsa.RSAPrivateCrtKeyImpl key, boolean verify)
        throws BadPaddingException {
        return crtCrypt_Native(msg, key, verify);
    }

    /**
     * RSA public key ops. Simple modPow().
     */
    synchronized private static byte[] crypt_Native(byte[] msg, sun.security.rsa.RSAPublicKeyImpl key)
        throws BadPaddingException {

        long nativePtr = key.getNativePtr();

        if (nativePtr == -1) {
            return null;
        }

        BigInteger n = key.getModulus();
        byte[] output = new byte[getByteLength(n)];

        int outputLen = nativeCrypto.RSAEP(msg, msg.length, output, nativePtr);

        if (outputLen == -1) {
            return null;
        }
        return output;
    }

    /**
     * RSA private key operations with CRT. Algorithm and variable naming
     * are taken from PKCS#1 v2.1, section 5.1.2.
     */
    synchronized private static byte[] crtCrypt_Native(byte[] msg, sun.security.rsa.RSAPrivateCrtKeyImpl key,
            boolean verify) throws BadPaddingException {
        long nativePtr = key.getNativePtr();

        if (nativePtr == -1) {
            return null;
        }

        int verifyInt;
        BigInteger n = key.getModulus();
        int outputLen = getByteLength(n);
        byte[] output = new byte[outputLen];

        if(verify) {
            verifyInt = outputLen;
        } else {
            verifyInt = -1;
        }

        outputLen = nativeCrypto.RSADP(msg, msg.length, output, verifyInt, nativePtr);

        if (outputLen == -1) {
            return null;
        } else if (outputLen == -2) {
            throw new BadPaddingException("RSA private key operation failed");
        }

        return output;
    }
}
