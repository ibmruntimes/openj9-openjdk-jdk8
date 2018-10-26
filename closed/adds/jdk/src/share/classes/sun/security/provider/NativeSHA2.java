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

package sun.security.provider;

abstract class NativeSHA2 {

    /**
     * Native SHA-224 implementation class.
     */
    public static final class SHA224 extends NativeDigest {

        public SHA224() {
            super("SHA-224", 28, 2);
        }
    }

    /**
     * Native SHA-256 implementation class.
     */
    public static final class SHA256 extends NativeDigest {

        public SHA256() {
            super("SHA-256", 32, 1);
        }
    }
}
