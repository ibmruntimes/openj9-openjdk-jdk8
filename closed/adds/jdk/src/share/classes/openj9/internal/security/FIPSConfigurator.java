/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
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

package openj9.internal.security;

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Properties;
import java.security.AccessController;
import java.security.PrivilegedAction;

import sun.security.util.Debug;

/**
 * Configures the security providers when in FIPS mode.
 */
public final class FIPSConfigurator {

    private static final Debug debug = Debug.getInstance("semerufips");

    // FIPS mode enable check, only supported on Linux x64.
    private static final boolean userEnabledFIPS;
    private static final boolean isFIPSSupported;
    private static final boolean shouldEnableFIPS;

    static {
        String[] props = AccessController.doPrivileged(
                new PrivilegedAction<String[]>() {
                    @Override
                    public String[] run() {
                        return new String[] {System.getProperty("semeru.fips"),
                                System.getProperty("os.name"),
                                System.getProperty("os.arch")};
                    }
                });
        userEnabledFIPS = Boolean.parseBoolean(props[0]);
        isFIPSSupported = "Linux".equalsIgnoreCase(props[1])
                && "amd64".equalsIgnoreCase(props[2]);
        shouldEnableFIPS = userEnabledFIPS && isFIPSSupported;
    }

    private FIPSConfigurator() {
        super();
    }

    /**
     * FIPS mode will be enabled only if the semeru.fips system
     * property is true (default as false).
     *
     * @return true if FIPS is enabled
     */
    public static boolean enableFIPS() {
        return shouldEnableFIPS;
    }

    /**
     * Remove the security providers and only add the FIPS security providers.
     *
     * @param props the java.security properties
     * @return true if the FIPS properties loaded successfully
     */
    public static boolean configureFIPS(Properties props) {
        boolean loadedProps = false;

        // Check if FIPS is supported on this platform.
        if (userEnabledFIPS && !isFIPSSupported) {
            throw new RuntimeException("FIPS is not supported on this platform.");
        }

        try {
            if (shouldEnableFIPS) {
                if (debug != null) {
                    debug.println("FIPS mode detected, loading properties");
                }

                // Remove all security providers.
                Iterator<Entry<Object, Object>> i = props.entrySet().iterator();
                while (i.hasNext()) {
                    Entry<Object, Object> e = i.next();
                    if (((String) e.getKey()).startsWith("security.provider")) {
                        if (debug != null) {
                            debug.println("Removing provider: " + e);
                        }
                        i.remove();
                    }
                }

                // Add FIPS security providers.
                props.put("security.provider.1", "SunPKCS11 ${java.home}/conf/security/nss.fips.cfg");
                props.put("security.provider.2", "SUN");
                props.put("security.provider.3", "SunEC");
                props.put("security.provider.4", "SunJSSE");

                // Add FIPS security properties.
                props.put("keystore.type", "PKCS11");
                System.setProperty("javax.net.ssl.keyStore", "NONE");

                // Add FIPS disabled algorithms.
                String disabledAlgorithms = props.get("jdk.tls.disabledAlgorithms")
                        + ", X25519, X448"
                        + ", SSLv3, TLSv1, TLSv1.1"
                        + ", TLS_CHACHA20_POLY1305_SHA256"
                        + ", TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
                        + ", TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
                        + ", TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
                        + ", TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
                        + ", TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
                        + ", TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
                        + ", TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256"
                        + ", TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256"
                        + ", TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA"
                        + ", TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256"
                        + ", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                        + ", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                        + ", TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
                        + ", TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
                        + ", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                        + ", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                        + ", TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                        + ", TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
                props.put("jdk.tls.disabledAlgorithms", disabledAlgorithms);

                if (debug != null) {
                    debug.println("FIPS mode properties loaded");
                    debug.println(props.toString());
                }

                loadedProps = true;
            }
        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to load FIPS configuration");
                e.printStackTrace();
            }
        }
        return loadedProps;
    }
}
