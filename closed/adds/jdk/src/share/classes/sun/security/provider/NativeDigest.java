/*
 * Copyright (c) 2003, 2014, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2018, 2018 All Rights Reserved
 * ===========================================================================
 */

package sun.security.provider;

import java.security.MessageDigestSpi;
import java.security.DigestException;
import java.security.ProviderException;

import static sun.security.provider.ByteArrayAccess.*;

import jdk.crypto.jniprovider.NativeCrypto;

abstract class NativeDigest extends MessageDigestSpi implements Cloneable {

    private long context;
    // one element byte array, temporary storage for update(byte)
    private byte[] oneByte;
    // algorithm name to use in the exception message
    private final String algorithm;
    // length of the message digest in bytes
    private final int digestLength;
    private final int algIndx;
    // number of bytes processed so far. subclasses should not modify
    // this value.
    // also used as a flag to indicate reset status
    // -1: need to call engineReset() before next call to update()
    //  0: is already reset
    private long bytesProcessed;

    /**
     * Main constructor.
     */
    NativeDigest(String algorithm, int digestLength, int algIndx) {
        super();
        this.algorithm = algorithm;
        this.digestLength = digestLength;
        this.algIndx = algIndx;
        this.context = NativeCrypto.DigestCreateContext(0, algIndx);
    }

    // return digest length. See JCA doc.
    protected final int engineGetDigestLength() {

        return digestLength;
    }

    // single byte update. See JCA doc.
    protected final void engineUpdate(byte b) {

        if (oneByte == null) {
            oneByte = new byte[1];
        }
        oneByte[0] = b;
        engineUpdate(oneByte, 0, 1);
    }

    // array update. See JCA doc.
    protected final void engineUpdate(byte[] b, int ofs, int len) {
        if (len == 0) {
            return;
        }

        if ((ofs < 0) || (len < 0) || (ofs > b.length - len)) {
            throw new ArrayIndexOutOfBoundsException();
        }

        if (bytesProcessed < 0) {
            engineReset();
        }

        bytesProcessed += len;

        NativeCrypto.DigestUpdate(context, b, ofs, len);
    }

    // reset this object. See JCA doc.
    protected final void engineReset() {
        if (bytesProcessed == 0) {
            // already reset, ignore
            return;
        }

        bytesProcessed = 0;
    }

    // return the digest. See JCA doc.
    protected final byte[] engineDigest() {
        byte[] b = new byte[digestLength];

        try {
            engineDigest(b, 0, b.length);
        } catch (DigestException e) {
            throw (ProviderException)
                new ProviderException("Internal error").initCause(e);
        }

        return b;
    }

    // return the digest in the specified array. See JCA doc.
    protected final int engineDigest(byte[] out, int ofs, int len)
            throws DigestException {

        if (len < digestLength) {
            throw new DigestException("Length must be at least "
                + digestLength + " for " + algorithm + "digests");
        }

        if ((ofs < 0) || (len < 0) || (ofs > out.length - len)) {
            throw new DigestException("Buffer too short to store digest");
        }

        if (bytesProcessed < 0) {
            engineReset();
        }

        NativeCrypto.DigestComputeAndReset(context, null, 0, 0, out, ofs, len);

        bytesProcessed = -1;
        return digestLength;
    }

    public Object clone() throws CloneNotSupportedException {
        NativeDigest copy = (NativeDigest) super.clone();
        copy.context    = NativeCrypto.DigestCreateContext(context, algIndx);
        return copy;
    }

}
