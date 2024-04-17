/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2024 All Rights Reserved
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

package sun.security.pkcs11.wrapper;

/**
 * This class represents the necessary parameters required by the
 * CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE and
 * CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH mechanisms as defined
 * in CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS structure.<p>
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
 *     CK_MECHANISM_TYPE prfHashMechanism;
 *     CK_BYTE_PTR pSessionHash;
 *     CK_ULONG ulSessionHashLen;
 *     CK_VERSION_PTR pVersion;
 * } CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS;
 * </PRE>
 *
 */
public class CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS {

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_MECHANISM_TYPE prfHashMechanism;
     * </PRE>
     */
    public final long prfHashMechanism;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BYTE_PTR pSessionHash;
     * </PRE>
     */
    public final byte[] pSessionHash;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_VERSION_PTR pVersion;
     * </PRE>
     */
    public final CK_VERSION pVersion;

    public CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS(
            long prfHashMechanism, byte[] pSessionHash,
            CK_VERSION pVersion) {
        this.prfHashMechanism = prfHashMechanism;
        this.pSessionHash = pSessionHash;
        this.pVersion = pVersion;
    }

    /**
     * Returns the string representation of
     * CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS.
     *
     * @return the string representation of
     * CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS
     */
    @Override
    public String toString() {
        StringBuilder buffer = new StringBuilder();

        buffer.append(Constants.INDENT);
        buffer.append("prfHashMechanism: ");
        buffer.append(prfHashMechanism);
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("pSessionHash: ");
        buffer.append(Functions.toHexString(pSessionHash));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("pVersion: ");
        buffer.append(pVersion);

        return buffer.toString();
    }

}
