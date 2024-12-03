/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2024 All Rights Reserved
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

import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Provider.Service;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import sun.security.util.Debug;

/**
 * Configures the security providers when in restricted security mode.
 */
public final class RestrictedSecurity {

    private static final Debug debug = Debug.getInstance("semerufips");

    // Restricted security mode enable check.
    private static final boolean userEnabledFIPS;
    private static boolean isFIPSSupported;
    private static boolean isFIPSEnabled;

    private static final boolean allowSetProperties;

    private static final boolean isNSSSupported;
    private static final boolean isOpenJCEPlusSupported;

    private static final boolean userSetProfile;
    private static final boolean shouldEnableSecurity;
    private static String selectedProfile;
    private static String profileID;

    private static boolean securityEnabled;

    private static String userSecurityID;

    private static ProfileParser profileParser;

    private static RestrictedSecurityProperties restricts;

    private static final Set<String> unmodifiableProperties = new HashSet<>();

    private static final Map<String, List<String>> supportedPlatformsNSS = new HashMap<>();
    private static final Map<String, List<String>> supportedPlatformsOpenJCEPlus = new HashMap<>();

    static {
        supportedPlatformsNSS.put("Arch", Arrays.asList("amd64", "ppc64le", "s390x"));
        supportedPlatformsNSS.put("OS", Arrays.asList("Linux"));

        supportedPlatformsOpenJCEPlus.put("Arch", Arrays.asList("amd64", "ppc64"));
        supportedPlatformsOpenJCEPlus.put("OS", Arrays.asList("Linux", "AIX", "Windows"));

        @SuppressWarnings("removal")
        String[] props = AccessController.doPrivileged(
                new PrivilegedAction<String[]>() {
                    @Override
                    public String[] run() {
                        return new String[] { System.getProperty("semeru.fips"),
                                System.getProperty("semeru.customprofile"),
                                System.getProperty("os.name"),
                                System.getProperty("os.arch"),
                                System.getProperty("semeru.fips.allowsetproperties") };
                    }
                });

        boolean isOsSupported, isArchSupported;
        // Check whether the NSS FIPS solution is supported.
        isOsSupported = false;
        for (String os: supportedPlatformsNSS.get("OS")) {
            if (props[2].contains(os)) {
                isOsSupported = true;
            }
        }
        isArchSupported = false;
        for (String arch: supportedPlatformsNSS.get("Arch")) {
            if (props[3].contains(arch)) {
                isArchSupported = true;
            }
        }
        isNSSSupported = isOsSupported && isArchSupported;

        // Check whether the OpenJCEPlus FIPS solution is supported.
        isOsSupported = false;
        for (String os: supportedPlatformsOpenJCEPlus.get("OS")) {
            if (props[2].contains(os)) {
                isOsSupported = true;
            }
        }
        isArchSupported = false;
        for (String arch: supportedPlatformsOpenJCEPlus.get("Arch")) {
            if (props[3].contains(arch)) {
                isArchSupported = true;
            }
        }
        isOpenJCEPlusSupported = isOsSupported && isArchSupported;

        // Check the default solution to see if FIPS is supported.
        isFIPSSupported = isNSSSupported;

        userEnabledFIPS = Boolean.parseBoolean(props[0]);
        allowSetProperties = Boolean.parseBoolean(props[4]);

        if (userEnabledFIPS) {
            if (isFIPSSupported) {
                // Set to default profile for the default FIPS solution.
                selectedProfile = "NSS.140-2";
            }
        }

        // If user has specified a profile, use that
        if (props[1] != null) {
            selectedProfile = props[1];
            userSetProfile = true;
        } else {
            userSetProfile = false;
        }

        // Check if FIPS is supported on this platform without explicitly setting a profile.
        if (userEnabledFIPS && !isFIPSSupported && !userSetProfile) {
            printStackTraceAndExit("FIPS mode is not supported on this platform by default.\n"
                    + " Use the semeru.customprofile system property to use an available FIPS-compliant profile.\n"
                    + " Note: Not all platforms support FIPS at the moment.");
        }

        shouldEnableSecurity = (userEnabledFIPS && isFIPSSupported) || userSetProfile;
    }

    private RestrictedSecurity() {
        super();
    }

    /**
     * Check loaded profiles' hash values.
     *
     * In order to avoid unintentional changes in profiles and incentivize
     * extending profiles, instead of altering them, a digest of the profile
     * is calculated and compared to the expected value.
     */
    public static void checkHashValues() {
        if (profileParser != null) {
            profileParser.checkHashValues();
            profileParser = null;
        }
    }

    /**
     * Check if restricted security mode is enabled.
     *
     * Restricted security mode is enabled when, on supported platforms,
     * the semeru.customprofile system property is used to set a
     * specific security profile or the semeru.fips system property is
     * set to true.
     *
     * @return true if restricted security mode is enabled
     */
    public static boolean isEnabled() {
        return securityEnabled;
    }

    /**
     * Get restricted security mode secure random algorithm.
     *
     * Restricted security mode secure random algorithm can only
     * be called in restricted security mode.
     *
     * @return the secure random algorithm
     */
    public static String getRandomAlgorithm() {
        if (!securityEnabled) {
            printStackTraceAndExit(
                    "Restricted security mode secure random algorithm can only be used when restricted security mode is enabled.");
        }
        return restricts.jdkSecureRandomAlgorithm;
    }

    /**
     * Check if the FIPS mode is enabled.
     *
     * FIPS mode will be enabled when the semeru.fips system property is
     * true, and the RestrictedSecurity mode has been successfully initialized.
     *
     * @return true if FIPS is enabled
     */
    public static boolean isFIPSEnabled() {
        if (securityEnabled) {
            return isFIPSEnabled;
        }
        return false;
    }

    /**
     * Check if the service is allowed in restricted security mode.
     *
     * @param service the service to check
     * @return true if the service is allowed
     */
    public static boolean isServiceAllowed(Service service) {
        if (securityEnabled) {
            return restricts.isRestrictedServiceAllowed(service);
        }
        return true;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerName the provider to check
     * @return true if the provider is allowed
     */
    public static boolean isProviderAllowed(String providerName) {
        if (securityEnabled) {
            // Remove argument, e.g. -NSS-FIPS, if present.
            int pos = providerName.indexOf('-');
            if (pos >= 0) {
                providerName = providerName.substring(0, pos);
            }

            return restricts.isRestrictedProviderAllowed(providerName);
        }
        return true;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerClazz the provider class to check
     * @return true if the provider is allowed
     */
    public static boolean isProviderAllowed(Class<?> providerClazz) {
        if (securityEnabled) {
            String providerClassName = providerClazz.getName();

            // Check if the specified class extends java.security.Provider.
            if (java.security.Provider.class.isAssignableFrom(providerClazz)) {
                return restricts.isRestrictedProviderAllowed(providerClassName);
            }

            // For a class that doesn't extend java.security.Provider, no need to
            // check allowed or not allowed, always return true to load it.
            if (debug != null) {
                debug.println("The provider class " + providerClassName + " does not extend java.security.Provider.");
            }
        }
        return true;
    }

    /**
     * Figure out the full profile ID.
     *
     * Use the default or user selected profile and attempt to find
     * an appropriate entry in the java.security properties.
     *
     * If a profile cannot be found, or multiple defaults are discovered
     * for a single profile, an appropriate message is printed and the
     * system exits.
     *
     * @param props the java.security properties
     */
    private static void getProfileID(Properties props) {
        String potentialProfileID = "RestrictedSecurity." + selectedProfile;

        if (selectedProfile.indexOf('.') != -1) {
            /* The default profile is used, or the user specified the
             * full <profile.version>.
             */
            if (debug != null) {
                debug.println("Profile specified using full name (i.e., <profile.version>): "
                        + selectedProfile);
            }
            for (Object keyObject : props.keySet()) {
                if (keyObject instanceof String) {
                    String key = (String) keyObject;
                    if (key.startsWith(potentialProfileID)) {
                        profileID = potentialProfileID;
                        return;
                    }
                }
            }
            printStackTraceAndExit(selectedProfile + " is not present in the java.security file.");
        } else {
            /* The user specified the only the <profile> without
             * indicating the <version> part.
             */
            if (debug != null) {
                debug.println("Profile specified without version (i.e., <profile>): "
                        + selectedProfile);
            }
            String defaultMatch = null;
            boolean profileExists = false;
            String profilePrefix = potentialProfileID + '.';
            for (Object keyObject : props.keySet()) {
                if (keyObject instanceof String) {
                    String key = (String) keyObject;
                    if (key.startsWith(profilePrefix)) {
                        profileExists = true;
                        if (key.endsWith(".desc.default")) {
                            // Check if property is set to true.
                            if (Boolean.parseBoolean(props.getProperty(key))) {
                                // Check if multiple defaults exist and act accordingly.
                                if (defaultMatch == null) {
                                    defaultMatch = key.substring(0, key.length() - ".desc.default".length());
                                } else {
                                    printStackTraceAndExit("Multiple default RestrictedSecurity"
                                            + " profiles for " + selectedProfile);
                                }
                            }
                        }
                    }
                }
            }
            if (!profileExists) {
                printStackTraceAndExit(selectedProfile + " is not present in the java.security file.");
            } else if (defaultMatch == null) {
                printStackTraceAndExit("No default RestrictedSecurity profile was found for "
                        + selectedProfile);
            } else {
                profileID = defaultMatch;
            }
        }
    }

    private static void checkIfKnownProfileSupported() {
        if (profileID.contains("NSS") && !isNSSSupported) {
            printStackTraceAndExit("NSS RestrictedSecurity profiles are not supported"
                    + " on this platform.");
        }

        if (profileID.contains("OpenJCEPlus") && !isOpenJCEPlusSupported) {
            printStackTraceAndExit("OpenJCEPlus RestrictedSecurity profiles are not supported"
                    + " on this platform.");
        }

        if (debug != null) {
            debug.println("RestrictedSecurity profile " + profileID
                    + " is supported on this platform.");
        }
    }

    private static void checkFIPSCompatibility() {
        boolean isFIPSProfile = restricts.descIsFIPS;
        if (isFIPSProfile) {
            if (debug != null) {
                debug.println("RestrictedSecurity profile " + profileID
                        + " is specified as FIPS compliant.");
            }
            isFIPSEnabled = true;
        } else {
            printStackTraceAndExit("RestrictedSecurity profile " + profileID
                    + " is not specified as FIPS compliant, but the semeru.fips"
                    + " system property is set to true.");
        }
    }

    /**
     * Check whether a security property can be set.
     *
     * A security property that is FIPS-related and can be set by a RestrictedSecurity
     * profile, while FIPS security mode is enabled, cannot be reset programmatically.
     *
     * Every time an attempt to set a security property is made, a check is
     * performed. If the above scenario holds true, a SecurityException is
     * thrown.
     *
     * One can override this behaviour and allow the user to set any security
     * property through the use of {@code -Dsemeru.fips.allowsetproperties=true}.
     *
     * @param key the security property that the user wants to set
     * @throws SecurityException
     *         if the security property is set by the profile and cannot
     *         be altered
     */
    public static void checkSetSecurityProperty(String key) {
        if (debug != null) {
            debug.println("RestrictedSecurity: Checking whether property '"
                    + key + "' can be set.");
        }

        /*
         * Only disallow setting of security properties that are FIPS-related,
         * if FIPS has been enabled.
         *
         * Allow any change, if the 'semeru.fips.allowsetproperties' flag is set to true.
         */
        if (unmodifiableProperties.contains(key)) {
            if (debug != null) {
                debug.println("RestrictedSecurity: Property '" + key + "' cannot be set.");
                debug.println("If you want to override the check and allow all security"
                        + "properties to be set, use '-Dsemeru.fips.allowsetproperties=true'.");
                debug.println("BEWARE: You might not be FIPS compliant if you select to override!");
            }
            throw new SecurityException("Property '" + key
                    + "' cannot be set programmatically when in FIPS mode");
        }

        if (debug != null) {
            debug.println("RestrictedSecurity: Property '"
                    + key + "' can be set without issue.");
        }
    }

    /**
     * Remove the security providers and only add restricted security providers.
     *
     * @param props the java.security properties
     * @return true if restricted security properties loaded successfully
     */
    public static boolean configure(Properties props) {
        // Check if restricted security is already initialized.
        if (securityEnabled) {
            printStackTraceAndExit("Restricted security mode is already initialized, it can't be initialized twice.");
        }

        try {
            if (shouldEnableSecurity) {
                if (debug != null) {
                    debug.println("Restricted security mode is being enabled...");
                }

                getProfileID(props);
                checkIfKnownProfileSupported();

                // Initialize restricted security properties from java.security file.
                profileParser = new ProfileParser(profileID, props);
                restricts = profileParser.getProperties();

                // Restricted security properties checks.
                restrictsCheck();

                // Remove all security providers.
                for (Iterator<Map.Entry<Object, Object>> i = props.entrySet().iterator(); i.hasNext();) {
                    Map.Entry<Object, Object> e = i.next();
                    String key = (String) e.getKey();
                    if (key.startsWith("security.provider")) {
                        if (debug != null) {
                            debug.println("Removing provider: " + e);
                        }
                        i.remove();
                    }
                }

                // Add restricted security providers.
                setProviders(props);

                // Add restricted security Properties.
                setProperties(props);

                if (debug != null) {
                    debug.println("Restricted security mode loaded.");
                    debug.println("Restricted security mode properties: " + props.toString());
                }

                securityEnabled = true;
            }
        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to load restricted security mode configurations.");
            }
            printStackTraceAndExit(e);
        }
        return securityEnabled;
    }

    /**
     * Add restricted security providers.
     *
     * @param props the java.security properties
     */
    private static void setProviders(Properties props) {
        if (debug != null) {
            debug.println("Adding restricted security provider.");
        }

        int pNum = 0;
        for (String provider : restricts.providers) {
            pNum += 1;
            props.setProperty("security.provider." + pNum, provider);
            if (debug != null) {
                debug.println("Added restricted security provider: " + provider);
            }
        }
    }

    /**
     * Add restricted security properties.
     *
     * @param props the java.security properties
     */
    private static void setProperties(Properties props) {
        if (debug != null) {
            debug.println("Adding restricted security properties.");
        }

        Map<String, String> propsMapping = new HashMap<>();

        // JDK properties name as key, restricted security properties value as value.
        propsMapping.put("jdk.tls.disabledNamedCurves", restricts.jdkTlsDisabledNamedCurves);
        propsMapping.put("jdk.tls.disabledAlgorithms", restricts.jdkTlsDisabledAlgorithms);
        propsMapping.put("jdk.tls.ephemeralDHKeySize", restricts.jdkTlsEphemeralDHKeySize);
        propsMapping.put("jdk.tls.legacyAlgorithms", restricts.jdkTlsLegacyAlgorithms);
        propsMapping.put("jdk.certpath.disabledAlgorithms", restricts.jdkCertpathDisabledAlgorithms);
        propsMapping.put("jdk.security.legacyAlgorithms", restricts.jdkSecurityLegacyAlgorithms);

        if (userEnabledFIPS && !allowSetProperties) {
            // Add all properties that cannot be modified.
            unmodifiableProperties.addAll(propsMapping.keySet());
        }

        for (Map.Entry<String, String> entry : propsMapping.entrySet()) {
            String jdkPropsName = entry.getKey();
            String propsNewValue = entry.getValue();

            if (!isNullOrBlank(propsNewValue)) {
                props.setProperty(jdkPropsName, propsNewValue);
                if (debug != null) {
                    debug.println("Added restricted security properties, with property: "
                            + jdkPropsName + " value: " + propsNewValue);
                }
            }
        }

        // For keyStore and keystore.type, old value not needed, just set the new value.
        String keyStoreType = restricts.keyStoreType;
        if (!isNullOrBlank(keyStoreType)) {
            props.setProperty("keystore.type", keyStoreType);
        }
        String keyStore = restricts.keyStore;
        if (!isNullOrBlank(keyStore)) {
            // SSL property "javax.net.ssl.keyStore" set at the JVM level via system properties.
            System.setProperty("javax.net.ssl.keyStore", keyStore);
        }
    }

    /**
     * Check restricted security properties.
     */
    private static void restrictsCheck() {
        // Check restricts object.
        if (restricts == null) {
            printStackTraceAndExit("Restricted security property is null.");
        }

        // Check if the SunsetDate expired.
        if (isPolicySunset(restricts.descSunsetDate)) {
            printStackTraceAndExit("Restricted security policy expired.");
        }

        // Check secure random settings.
        if (isNullOrBlank(restricts.jdkSecureRandomAlgorithm)) {
            printStackTraceAndExit("Restricted security mode secure random is missing.");
        }

        // If user enabled FIPS, check whether chosen profile is applicable.
        if (userEnabledFIPS) {
            checkFIPSCompatibility();
        }
    }

    /**
     * Check if restricted security policy is sunset.
     *
     * @param descSunsetDate the sunset date from java.security
     * @return true if restricted security policy sunset
     */
    private static boolean isPolicySunset(String descSunsetDate) {
        boolean isSunset = false;
        // Only check if a sunset date is specified in the profile.
        if (!isNullOrBlank(descSunsetDate)) {
            try {
                isSunset = LocalDate.parse(descSunsetDate, DateTimeFormatter.ofPattern("yyyy-MM-dd"))
                        .isBefore(LocalDate.now());
            } catch (DateTimeParseException except) {
                printStackTraceAndExit(
                        "Restricted security policy sunset date is incorrect, the correct format is yyyy-MM-dd.");
            }
        }

        if (debug != null) {
            debug.println("Restricted security policy is sunset: " + isSunset);
        }
        return isSunset;
    }

    /**
     * Check if the input string is blank.
     *
     * @param string the input string
     * @return true if the input string is blank
     */
    private static boolean isBlank(String string) {
        return string.trim().isEmpty();
    }

    /**
     * Check if the input string is null or blank.
     *
     * @param string the input string
     * @return true if the input string is null or blank
     */
    private static boolean isNullOrBlank(String string) {
        return (string == null) || isBlank(string);
    }

    private static void printStackTraceAndExit(Exception exception) {
        exception.printStackTrace();
        System.exit(1);
    }

    private static void printStackTraceAndExit(String message) {
        printStackTraceAndExit(new RuntimeException(message));
    }

    /**
     * Check if the input string is asterisk (*).
     *
     * @param string input string for checking
     * @return true if the input string is asterisk
     */
    private static boolean isAsterisk(String string) {
        return "*".equals(string);
    }

    /**
     * This class is used to save and operate on restricted security
     * properties which are loaded from the java.security file.
     */
    private static final class RestrictedSecurityProperties {
        private final String profileID;

        private final String descName;
        private final boolean descIsDefault;
        private final boolean descIsFIPS;
        private final String descNumber;
        private final String descPolicy;
        private final String descSunsetDate;

        // Security properties.
        private final String jdkTlsDisabledNamedCurves;
        private final String jdkTlsDisabledAlgorithms;
        private final String jdkTlsEphemeralDHKeySize;
        private final String jdkTlsLegacyAlgorithms;
        private final String jdkCertpathDisabledAlgorithms;
        private final String jdkSecurityLegacyAlgorithms;
        private final String keyStoreType;
        private final String keyStore;

        // For SecureRandom.
        final String jdkSecureRandomAlgorithm;

        final String jdkFipsMode;

        // Provider with argument (provider name + optional argument).
        private final List<String> providers;
        // Provider without argument.
        private final List<String> providersFullyQualifiedClassName;
        // The map is keyed by provider name.
        private final Map<String, Constraint[]> providerConstraints;

        private RestrictedSecurityProperties(String profileID, ProfileParser parser) {
            this.profileID = profileID;

            this.descName = parser.getProperty("descName");
            this.descIsDefault = parser.descIsDefault;
            this.descIsFIPS = parser.descIsFIPS;
            this.descNumber = parser.getProperty("descNumber");

            this.descPolicy = parser.getProperty("descPolicy");
            this.descSunsetDate = parser.getProperty("descSunsetDate");

            // Security properties.
            this.jdkTlsDisabledNamedCurves = parser.getProperty("jdkTlsDisabledNamedCurves");
            this.jdkTlsDisabledAlgorithms = parser.getProperty("jdkTlsDisabledAlgorithms");
            this.jdkTlsEphemeralDHKeySize = parser.getProperty("jdkTlsEphemeralDHKeySize");
            this.jdkTlsLegacyAlgorithms = parser.getProperty("jdkTlsLegacyAlgorithms");
            this.jdkCertpathDisabledAlgorithms = parser.getProperty("jdkCertpathDisabledAlgorithms");
            this.jdkSecurityLegacyAlgorithms = parser.getProperty("jdkSecurityLegacyAlgorithms");
            this.keyStoreType = parser.getProperty("keyStoreType");
            this.keyStore = parser.getProperty("keyStore");

            // For SecureRandom.
            this.jdkSecureRandomAlgorithm = parser.getProperty("jdkSecureRandomAlgorithm");

            this.jdkFipsMode = parser.getProperty("jdkFipsMode");

            this.providers = new ArrayList<>(parser.providers);
            this.providersFullyQualifiedClassName = new ArrayList<>(parser.providersFullyQualifiedClassName);
            this.providerConstraints = parser.providerConstraints
                                             .entrySet()
                                             .stream()
                                             .collect(Collectors.toMap(
                                                     e -> e.getKey(),
                                                     e -> e.getValue().toArray(new Constraint[0])
                                             ));

            if (debug != null) {
                // Print information of utilized security profile.
                listUsedProfile();
            }
        }

        /**
         * Check if the Service is allowed in restricted security mode.
         *
         * @param service the Service to check
         * @return true if the Service is allowed
         */
        boolean isRestrictedServiceAllowed(Service service) {
            Provider provider = service.getProvider();
            String providerClassName = provider.getClass().getName();

            if (debug != null) {
                debug.println("Checking service " + service.toString() + " offered by provider " + providerClassName + ".");
            }

            Constraint[] constraints = providerConstraints.get(providerClassName);

            if (constraints == null) {
                // Disallow unknown providers.
                if (debug != null) {
                    debug.println("Security constraints check."
                            + " Disallow unknown provider: " + providerClassName);
                }
                return false;
            } else if (constraints.length == 0) {
                // Allow this provider with no constraints.
                if (debug != null) {
                    debug.println("No constraints for provider " + providerClassName + ".");
                }
                return true;
            }

            // Check the constraints of this provider.
            String type = service.getType();
            String algorithm = service.getAlgorithm();

            if (debug != null) {
                debug.println("Security constraints check of provider.");
            }
            for (Constraint constraint : constraints) {
                String cType = constraint.type;
                String cAlgorithm = constraint.algorithm;
                String cAttribute = constraint.attributes;
                if (debug != null) {
                    debug.println("Checking provider constraint:"
                                + "\n\tService type: " + cType
                                + "\n\tAlgorithm: " + cAlgorithm
                                + "\n\tAttributes: " + cAttribute);
                }

                if (!isAsterisk(cType) && !type.equalsIgnoreCase(cType)) {
                    // The constraint doesn't apply to the service type.
                    if (debug != null) {
                        debug.println("The constraint doesn't apply to the service type.");
                    }
                    continue;
                }
                if (!isAsterisk(cAlgorithm) && !algorithm.equalsIgnoreCase(cAlgorithm)) {
                    // The constraint doesn't apply to the service algorithm.
                    if (debug != null) {
                        debug.println("The constraint doesn't apply to the service algorithm.");
                    }
                    continue;
                }

                // For type and algorithm match, and attribute is *.
                if (isAsterisk(cAttribute)) {
                    if (debug != null) {
                        debug.println("The following service:"
                                + "\n\tService type: " + type
                                + "\n\tAlgorithm: " + algorithm
                                + "\nis allowed in provider: " + providerClassName);
                    }
                    return true;
                }

                // For type and algorithm match, and attribute is not *.
                // Then continue checking attributes.
                String[] cAttributeArray = cAttribute.split(":");

                // For each attribute, must be all matched for return allowed.
                for (String attribute : cAttributeArray) {
                    String[] input = attribute.split("=", 2);

                    String cName = input[0].trim();
                    String cValue = input[1].trim();
                    String sValue = service.getAttribute(cName);
                    if (debug != null) {
                        debug.println("Checking specific attribute with:"
                                + "\n\tName: " + cName
                                + "\n\tValue: " + cValue
                                + "\nagainst the service attribute value: " + sValue);
                    }
                    if ((sValue == null) || !cValue.equalsIgnoreCase(sValue)) {
                        // If any attribute doesn't match, return service is not allowed.
                        if (debug != null) {
                            debug.println("Attributes don't match!");
                            debug.println("The following service:"
                                        + "\n\tService type: " + type
                                        + "\n\tAlgorithm: " + algorithm
                                        + "\n\tAttribute: " + cAttribute
                                        + "\nis NOT allowed in provider: " + providerClassName);
                        }
                        return false;
                    }
                    if (debug != null) {
                        debug.println("Attributes match!");
                    }
                }
                if (debug != null) {
                    debug.println("All attributes matched!");
                    debug.println("The following service:"
                                + "\n\tService type: " + type
                                + "\n\tAlgorithm: " + algorithm
                                + "\n\tAttribute: " + cAttribute
                                + "\nis allowed in provider: " + providerClassName);
                }
                return true;
            }

            // No match for any constraint, return NOT allowed.
            if (debug != null) {
                debug.println("Could not find a constraint to match.");
                debug.println("The following service:"
                            + "\n\tService type: " + type
                            + "\n\tAlgorithm: " + algorithm
                            + "\nis NOT allowed in provider: " + providerClassName);
            }
            return false;
        }

        /**
         * Check if the provider is allowed in restricted security mode.
         *
         * @param providerClassName the provider to check
         * @return true if the provider is allowed
         */
        boolean isRestrictedProviderAllowed(String providerClassName) {
            if (debug != null) {
                debug.println("Checking the provider " + providerClassName + " in restricted security mode.");
            }

            // Check if the provider fully-qualified cLass name is in restricted
            // security provider list. If not, the provider won't be registered.
            if (providersFullyQualifiedClassName.contains(providerClassName)) {
                if (debug != null) {
                    debug.println("The provider " + providerClassName + " is allowed in restricted security mode.");
                }
                return true;
            }

            if (debug != null) {
                debug.println("The provider " + providerClassName + " is not allowed in restricted security mode.");

                debug.println("Stack trace:");
                StackTraceElement[] elements = Thread.currentThread().getStackTrace();
                for (int i = 1; i < elements.length; i++) {
                    StackTraceElement stack = elements[i];
                    debug.println("\tat " + stack.getClassName() + "." + stack.getMethodName() + "("
                            + stack.getFileName() + ":" + stack.getLineNumber() + ")");
                }
            }
            return false;
        }

        /**
         * List the RestrictedSecurity profile currently used.
         */
        private void listUsedProfile() {
            System.out.println();
            System.out.println("Utilized Restricted Security Profile Info:");
            System.out.println("==========================================");
            System.out.println("The Restricted Security profile used is: " + profileID);
            System.out.println();
            System.out.println(profileID + " Profile Info:");
            System.out.println("==========================================");
            printProperty(profileID + ".desc.name: ", descName);
            printProperty(profileID + ".desc.default: ", "" + descIsDefault);
            printProperty(profileID + ".desc.fips: ", "" + descIsFIPS);
            printProperty(profileID + ".fips.mode: ", jdkFipsMode);
            printProperty(profileID + ".desc.number: ", descNumber);
            printProperty(profileID + ".desc.policy: ", descPolicy);
            printProperty(profileID + ".desc.sunsetDate: ", descSunsetDate);
            System.out.println();

            // List providers.
            System.out.println(profileID + " Profile Providers:");
            System.out.println("===============================================");
            for (int providerPosition = 0; providerPosition < providers.size(); providerPosition++) {
                printProperty(profileID + ".jce.provider." + (providerPosition + 1) + ": ",
                        providers.get(providerPosition));
                String providerFullyQualifiedClassName = providersFullyQualifiedClassName.get(providerPosition);
                for (Constraint providerConstraint : providerConstraints.get(providerFullyQualifiedClassName)) {
                    System.out.println("\t" + providerConstraint.toString());
                }
            }
            System.out.println();

            // List profile restrictions.
            System.out.println(profileID + " Profile Restrictions:");
            System.out.println("==================================================");
            printProperty(profileID + ".tls.disabledNamedCurves: ", jdkTlsDisabledNamedCurves);
            printProperty(profileID + ".tls.disabledAlgorithms: ", jdkTlsDisabledAlgorithms);
            printProperty(profileID + ".tls.ephemeralDHKeySize: ", jdkTlsEphemeralDHKeySize);
            printProperty(profileID + ".tls.legacyAlgorithms: ", jdkTlsLegacyAlgorithms);
            printProperty(profileID + ".jce.certpath.disabledAlgorithms: ", jdkCertpathDisabledAlgorithms);
            printProperty(profileID + ".jce.legacyAlgorithms: ", jdkSecurityLegacyAlgorithms);
            System.out.println();

            printProperty(profileID + ".keystore.type: ", keyStoreType);
            printProperty(profileID + ".javax.net.ssl.keyStore: ", keyStore);
            printProperty(profileID + ".securerandom.algorithm: ", jdkSecureRandomAlgorithm);
            System.out.println();
        }

        private static void printProperty(String name, String value) {
            if (value != null) {
                String valueToPrint = (value.isEmpty()) ? "EMPTY" : value;
                System.out.println(name + valueToPrint);
            } else if (debug != null) {
                debug.println("Nothing to print. Value of property " + name + " is null.");
            }
        }
    }

    private static final class ProfileParser {
        // Properties specified through the profile.
        private final Map<String, String> profileProperties;
        private boolean descIsDefault;
        private boolean descIsFIPS;

        // Provider with argument (provider name + optional argument).
        private final List<String> providers;
        // Provider without argument.
        private final List<String> providersFullyQualifiedClassName;
        // The map is keyed by provider name.
        private final Map<String, List<Constraint>> providerConstraints;

        private final String profileID;

        private final Map<String, String> profilesHashes;
        private final Map<String, List<String>> profilesInfo;

        private final Set<String> parsedProfiles;

        // The java.security properties.
        private final Properties securityProps;

        private final Set<String> profileCheckPropertyNames;
        private final Set<String> profileCheckProviderNames;

        /**
         *
         * @param id    the restricted security custom profile ID
         * @param props the java.security properties
         */
        private ProfileParser(String id, Properties props) {
            Objects.requireNonNull(props);

            profileID = id;
            securityProps = props;

            profileProperties = new HashMap<>();

            providers = new ArrayList<>();
            providersFullyQualifiedClassName = new ArrayList<>();
            providerConstraints = new HashMap<>();

            profilesHashes = new HashMap<>();
            profilesInfo = new HashMap<>();

            parsedProfiles = new HashSet<>();

            profileCheckPropertyNames = new HashSet<>();
            profileCheckProviderNames = new HashSet<>();

            // Initialize the properties.
            init(profileID);

            checkProfileCheck(profileID);
        }

        private RestrictedSecurityProperties getProperties() {
            return new RestrictedSecurityProperties(this.profileID, this);
        }

        private boolean isFIPS1402Profile(String profileID) {
            return "140-2".equals(securityProps.getProperty(profileID + ".fips.mode"));
        }

        /**
         * Initialize restricted security properties.
         */
        private void init(String profileID) {
            if (debug != null) {
                debug.println("Initializing restricted security properties for '" + profileID + "'.");
            }

            if (!parsedProfiles.add(profileID)) {
                printStackTraceAndExit(profileID + " has already been parsed. Potential infinite recursion.");
            }

            loadProfileCheck(profileID);

            String profileExtends = profileID + ".extends";
            String potentialExtendsProfileID = parseProperty(securityProps.getProperty(profileExtends));
            if (potentialExtendsProfileID != null) { // If profile extends another profile.
                if (debug != null) {
                    debug.println("\t'" + profileID + "' extends '" + potentialExtendsProfileID + "'.");
                }

                profileCheckPropertyNames.remove(profileExtends);

                // Check if extended profile exists.
                String extendsProfileID = null;
                if (potentialExtendsProfileID.indexOf('.') != potentialExtendsProfileID.lastIndexOf('.')) {
                    // Extended profile id has at least 2 dots (meaning it's a full profile id).
                    int prefixLength = potentialExtendsProfileID.length();
                    for (Object keyObject : securityProps.keySet()) {
                        if (keyObject instanceof String) {
                            String key = (String) keyObject;
                            if (key.startsWith(potentialExtendsProfileID)) {
                                String suffix = key.substring(prefixLength);
                                if (suffix.startsWith(".desc")
                                ||  suffix.startsWith(".fips")
                                ||  suffix.startsWith(".javax")
                                ||  suffix.startsWith(".jce")
                                ||  suffix.startsWith(".securerandom")
                                ||  suffix.startsWith(".tls")
                                ) {
                                    /* If even one security property is found for this profile id,
                                    * then it is a valid one and there is no need to check more
                                    * properties.
                                    */
                                    extendsProfileID = potentialExtendsProfileID;
                                    break;
                                }
                            }
                        }
                    }
                    if (extendsProfileID == null) {
                        printStackTraceAndExit(potentialExtendsProfileID + " that is supposed to extend '"
                                + profileID + "' is not present in the java.security file or any appended files.");
                    }
                } else {
                    printStackTraceAndExit(potentialExtendsProfileID + " that is supposed to extend '"
                            + profileID + "' is not a full profile name.");
                }

                // Recursively call init() on extended profile.
                init(extendsProfileID);

                // Perform update based on current profile.
                update(profileID);
            } else {
                try {
                    List<String> allInfo = new ArrayList<>();
                    // Load restricted security providers from java.security properties.
                    initProviders(profileID, allInfo);
                    // Load restricted security properties from java.security properties.
                    loadProperties(profileID, allInfo);

                    String hashProperty = profileID + ".desc.hash";
                    String hashValue = securityProps.getProperty(hashProperty);
                    if (hashValue != null) {
                        // Save info to be hashed and expected result to be checked later.
                        profilesHashes.put(profileID, hashValue);
                        profilesInfo.put(profileID, allInfo);
                        profileCheckPropertyNames.remove(hashProperty);
                    } else if (!isFIPS1402Profile(profileID)) {
                        // A hash is mandatory, but not for older 140-2 profiles.
                        printStackTraceAndExit(profileID + " is a base profile, so a hash value is mandatory.");
                    }
                } catch (Exception e) {
                    if (debug != null) {
                        debug.println("Unable to initialize restricted security mode.");
                    }
                    printStackTraceAndExit(e);
                }
            }

            if (debug != null) {
                debug.println("Initialization of restricted security properties for '" + profileID + "' completed.");
            }
        }

        /**
         * Initialize restricted security properties.
         */
        private void update(String profileExtensionId) {
            try {
                List<String> allInfo = new ArrayList<>();
                // Load restricted security providers from java.security properties.
                updateProviders(profileExtensionId, allInfo);
                // Load restricted security properties from java.security properties.
                loadProperties(profileExtensionId, allInfo);

                String hashProperty = profileExtensionId + ".desc.hash";
                String hashValue = securityProps.getProperty(hashProperty);

                // Hash value is optional in extension profiles.
                if (hashValue != null) {
                    // Save info to be hashed and expected result to be checked later.
                    profilesHashes.put(profileID, hashValue);
                    profilesInfo.put(profileID, allInfo);
                    profileCheckPropertyNames.remove(hashProperty);
                }
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Unable to update restricted security properties for '" + profileExtensionId + "'.");
                }
                printStackTraceAndExit(e);
            }
        }

        private void parseProvider(String providerInfo, int providerPos, boolean update) {
            if (debug != null) {
                debug.println("\t\tLoading provider in position " + providerPos);
            }

            checkProviderFormat(providerInfo, update);

            int pos = providerInfo.indexOf('[');
            String providerName = (pos < 0) ? providerInfo.trim() : providerInfo.substring(0, pos).trim();
            // Provider with argument (provider name + optional argument).
            if (update) {
                providers.set(providerPos - 1, providerName);
            } else {
                providers.add(providerPos - 1, providerName);
            }

            // Remove the provider's optional arguments if there are.
            pos = providerName.indexOf(' ');
            if (pos >= 0) {
                providerName = providerName.substring(0, pos);
            }
            providerName = providerName.trim();

            boolean providerChanged = false;
            if (update) {
                String previousProviderName = providersFullyQualifiedClassName.get(providerPos - 1);
                providerChanged = !previousProviderName.equals(providerName);
                providersFullyQualifiedClassName.set(providerPos - 1, providerName);
            } else {
                providersFullyQualifiedClassName.add(providerPos - 1, providerName);
            }

            if (debug != null) {
                debug.println("\t\tLoaded provider in position " + providerPos + " named: " + providerName);
            }

            // Set the provided constraints for this provider.
            setConstraints(providerName, providerInfo, providerChanged);
        }

        private void removeProvider(String profileExtensionId, int providerPos) {
            if (debug != null) {
                debug.println("\t\tRemoving provider in position " + providerPos);
            }

            int numOfExistingProviders = providersFullyQualifiedClassName.size();

            // If this is the last provider, remove from all lists.
            if (providerPos == numOfExistingProviders) {
                if (debug != null) {
                    debug.println("\t\t\tLast provider. Only one to be removed.");
                }
                String providerRemoved = providersFullyQualifiedClassName.remove(providerPos - 1);
                providers.remove(providerPos - 1);
                providerConstraints.remove(providerRemoved);

                if (debug != null) {
                    debug.println("\t\tProvider " + providerRemoved + " removed.");
                }
                return;
            }

            // If there's more, check that all of the subsequent ones are set to be removed.
            for (int i = numOfExistingProviders; i >= providerPos; i--) {
                if (debug != null) {
                    debug.println("\t\t\tNot the last provider. More to be removed.");
                }

                String providerInfo = securityProps.getProperty(profileExtensionId + ".jce.provider." + i);
                if ((providerInfo == null) || !isBlank(providerInfo)) {
                    printStackTraceAndExit(
                        "Cannot specify an empty provider in position "
                                + providerPos + " when non-empty ones are specified after it.");
                }

                // Remove all of the providers that are set to empty.
                String providerRemoved = providersFullyQualifiedClassName.remove(i - 1);
                providers.remove(i - 1);
                providerConstraints.remove(providerRemoved);

                if (debug != null) {
                    debug.println("\t\tProvider " + providerRemoved + " removed.");
                }
            }
        }

        /**
         * Load restricted security provider.
         */
        private void initProviders(String profileID, List<String> allInfo) {
            if (debug != null) {
                debug.println("\tLoading providers of restricted security profile.");
            }

            for (int pNum = 1;; ++pNum) {
                String property = profileID + ".jce.provider." + pNum;
                String providerInfo = securityProps.getProperty(property);

                if (providerInfo == null) {
                    break;
                }

                if (isBlank(providerInfo)) {
                    printStackTraceAndExit(
                        "Cannot specify an empty provider in position "
                                + pNum + ". Nothing specified before.");
                }

                allInfo.add(property + "=" + providerInfo);

                parseProvider(providerInfo, pNum, false);
                profileCheckProviderNames.remove(property);
            }

            if (providers.isEmpty()) {
                printStackTraceAndExit(
                        "No providers are specified as part of the Restricted Security profile.");
            }

            if (debug != null) {
                debug.println("\tProviders of restricted security profile successfully loaded.");
            }
        }

        private void updateProviders(String profileExtensionId, List<String> allInfo) {
            boolean removedProvider = false;
            int numOfExistingProviders = providersFullyQualifiedClassName.size();
            // Deal with update of existing providers.
            for (int i = 1; i <= numOfExistingProviders; i++) {
                String property = profileExtensionId + ".jce.provider." + i;
                String providerInfo = securityProps.getProperty(property);
                if (providerInfo != null) {
                    allInfo.add(property + "=" + providerInfo);
                    if (!isBlank(providerInfo)) {
                        // Update the specific provider.
                        parseProvider(providerInfo, i, true);
                    } else {
                        // Remove provider(s) after checking.
                        removeProvider(profileExtensionId, i);
                        removedProvider = true;
                        break;
                    }
                    profileCheckProviderNames.remove(property);
                }
            }

            // Deal with additional providers added.
            for (int i = numOfExistingProviders + 1;; i++) {
                String property = profileExtensionId + ".jce.provider." + i;
                String providerInfo = securityProps.getProperty(property);

                if (providerInfo == null) {
                    break;
                }

                if (isBlank(providerInfo)) {
                    printStackTraceAndExit(
                        "Cannot specify an empty provider in position "
                            + i + ". Nothing specified before.");
                }

                if (removedProvider) {
                    printStackTraceAndExit(
                        "Cannot add a provider in position " + i
                            + " after removing the ones in previous positions.");
                }

                allInfo.add(property + "=" + providerInfo);

                parseProvider(providerInfo, i, false);
                profileCheckProviderNames.remove(property);
            }
        }

        private String getExistingValue(String property) {
            if (debug != null) {
                debug.println("\tGetting previous value of property: " + property);
            }

            // Look for values from profiles that this one extends.
            String existingValue = profileProperties.get(property);
            String debugMessage = "\t\tPrevious value from extended profile: ";

            // If there is no value, look for non-profile values in java.security file.
            if (existingValue == null) {
                debugMessage = "\t\tPrevious value from java.security file: ";
                String propertyKey;
                switch (property) {
                case "jdkCertpathDisabledAlgorithms":
                    propertyKey = "jdk.certpath.disabledAlgorithms";
                    break;
                case "jdkSecurityLegacyAlgorithms":
                    propertyKey = "jdk.security.legacyAlgorithms";
                    break;
                case "jdkTlsDisabledAlgorithms":
                    propertyKey = "jdk.tls.disabledAlgorithms";
                    break;
                case "jdkTlsDisabledNamedCurves":
                    propertyKey = "jdk.tls.disabledNamedCurves";
                    break;
                case "jdkTlsLegacyAlgorithms":
                    propertyKey = "jdk.tls.legacyAlgorithms";
                    break;
                default:
                    return null;
                }
                existingValue = securityProps.getProperty(propertyKey);
            }

            if ((debug != null) && (existingValue != null)) {
                debug.println(debugMessage + existingValue);
            }

            return existingValue;
        }

        /**
         * Load restricted security properties.
         */
        private void loadProperties(String profileID, List<String> allInfo) {
            if (debug != null) {
                debug.println("\tLoading properties of restricted security profile.");
            }

            setProperty("descName", profileID + ".desc.name", allInfo);
            if (setProperty("descIsDefaultString", profileID + ".desc.default", allInfo)) {
                descIsDefault = Boolean.parseBoolean(profileProperties.get("descIsDefaultString"));
            }
            if (setProperty("descIsFIPSString", profileID + ".desc.fips", allInfo)) {
                descIsFIPS = Boolean.parseBoolean(profileProperties.get("descIsFIPSString"));
            }
            setProperty("descNumber", profileID + ".desc.number", allInfo);
            setProperty("descPolicy", profileID + ".desc.policy", allInfo);
            setProperty("descSunsetDate", profileID + ".desc.sunsetDate", allInfo);

            setProperty("jdkTlsDisabledNamedCurves",
                    profileID + ".tls.disabledNamedCurves", allInfo);
            setProperty("jdkTlsDisabledAlgorithms",
                    profileID + ".tls.disabledAlgorithms", allInfo);
            setProperty("jdkTlsEphemeralDHKeySize",
                    profileID + ".tls.ephemeralDHKeySize", allInfo);
            setProperty("jdkTlsLegacyAlgorithms",
                    profileID + ".tls.legacyAlgorithms", allInfo);
            setProperty("jdkCertpathDisabledAlgorithms",
                    profileID + ".jce.certpath.disabledAlgorithms", allInfo);
            setProperty("jdkSecurityLegacyAlgorithms",
                    profileID + ".jce.legacyAlgorithms", allInfo);
            setProperty("keyStoreType",
                    profileID + ".keystore.type", allInfo);
            setProperty("keyStore",
                    profileID + ".javax.net.ssl.keyStore", allInfo);

            setProperty("jdkSecureRandomAlgorithm",
                    profileID + ".securerandom.algorithm", allInfo);
            setProperty("jdkFipsMode",
                    profileID + ".fips.mode", allInfo);

            if (debug != null) {
                debug.println("\tProperties of restricted security profile successfully loaded.");
            }
        }

        private void setConstraints(String providerName, String providerInfo, boolean providerChanged) {
            if (debug != null) {
                debug.println("\t\tLoading constraints for security provider: " + providerName);
            }

            List<Constraint> constraints = new ArrayList<>();

            providerInfo = providerInfo.replaceAll("\\s+", "");

            // Check whether constraints are specified for this provider.
            Pattern p = Pattern.compile("\\[.+\\]");
            Matcher m = p.matcher(providerInfo);
            if (!m.find()) {
                if (debug != null) {
                    debug.println("\t\t\tNo constraints for security provider: " + providerName);
                }
                providerConstraints.put(providerName, constraints);
                return;
            }

            // Check whether constraints are properly specified.
            final String typeRE = "\\w+";
            final String algoRE = "[A-Za-z0-9./_-]+";
            final String attrRE = "[A-Za-z0-9=*|.:]+";
            final String consRE = "\\{(" + typeRE + "),(" + algoRE + "),(" + attrRE + ")\\}";
            p = Pattern.compile(
                "\\["
                + "([+-]?)"             // option to append or remove
                + consRE                // at least one constraint
                + "(," + consRE + ")*"  // more constraints [optional]
                + "\\]");
            m = p.matcher(providerInfo);

            if (!m.find()) {
                printStackTraceAndExit("Incorrect constraint definition for provider " + providerName);
            }

            String action = m.group(1);

            // Parse all provided constraints.
            p = Pattern.compile(consRE);
            m = p.matcher(providerInfo);

            while (m.find()) {
                String inType = m.group(1);
                String inAlgorithm = m.group(2);
                String inAttributes = m.group(3);

                // Each attribute must includes 2 fields (key and value) or *.
                if (!isAsterisk(inAttributes)) {
                    String[] attributeArray = inAttributes.split(":");
                    for (String attribute : attributeArray) {
                        String[] in = attribute.split("=", 2);
                        if (in.length != 2) {
                            printStackTraceAndExit(
                                    "Constraint attributes format is incorrect: " + providerInfo);
                        }
                    }
                }
                Constraint constraint = new Constraint(inType, inAlgorithm, inAttributes);
                constraints.add(constraint);
            }

            // Differeriante between add, remove and override.
            if (isNullOrBlank(action)) {
                providerConstraints.put(providerName, constraints);
            } else {
                if (providerChanged) {
                    printStackTraceAndExit(
                        "Cannot append or remove constraints since the provider " + providerName
                        + " wasn't in this position in the profile extended.");
                }
                List<Constraint> existingConstraints = providerConstraints.get(providerName);
                if (existingConstraints == null) {
                    existingConstraints = new ArrayList<>();
                    providerConstraints.put(providerName, existingConstraints);
                }
                if (action.equals("+")) { // Appending constraints.
                    existingConstraints.addAll(constraints);
                } else { // Removing constraints.
                    for (Constraint toRemove : constraints) {
                        if (!existingConstraints.remove(toRemove)) {
                            printStackTraceAndExit(
                                    "Constraint " + toRemove + "is not part of existing constraints.");
                        }
                    }
                }
            }

            if (debug != null) {
                debug.println("\t\t\tSuccessfully loaded constraints for security provider: " + providerName);
            }
        }

        private void checkHashValues() {
            for (Map.Entry<String, String> entry : profilesHashes.entrySet()) {
                String profileID = entry.getKey();
                String hashValue = entry.getValue();
                List<String> allInfo = profilesInfo.get(profileID);

                if (debug != null) {
                    debug.println("Calculating hash for '" + profileID + "'.");
                }
                String[] hashInfo = hashValue.split(":");
                if (hashInfo.length != 2) {
                    printStackTraceAndExit("Incorrect definition of hash value for " + profileID);
                }

                String digestAlgo = hashInfo[0].trim();
                String expectedHash = hashInfo[1].trim();
                try {
                    MessageDigest md = MessageDigest.getInstance(digestAlgo);
                    byte[] allInfoArray = allInfo.stream()
                                                 .sorted()
                                                 .collect(Collectors.joining("\n"))
                                                 .getBytes(StandardCharsets.UTF_8);
                    byte[] resultHashArray = md.digest(allInfoArray);
                    StringBuilder hexString = new StringBuilder();
                    for (byte hashByte : resultHashArray) {
                        hexString.append(String.format("%02x", hashByte & 0xff));
                    }
                    String resultHashHex = hexString.toString();
                    if (debug != null) {
                        debug.println("\tCalculated hash for '" + profileID + "': " + resultHashHex);
                        debug.println("\tExpected hash for '" + profileID + "': " + expectedHash);
                    }
                    if (!resultHashHex.equalsIgnoreCase(expectedHash)) {
                        printStackTraceAndExit("Hex produced from profile is not the same is a "
                            + "base profile, so a hash value is mandatory.");
                    }
                } catch (NoSuchAlgorithmException nsae) {
                    if (debug != null) {
                        debug.println("The hash algorithm specified for '"
                            + profileID + "' is not available.");
                    }
                    printStackTraceAndExit(nsae);
                }
            }
        }

        /**
         * List audit info of all available RestrictedSecurity profiles.
         */
        private void listAvailableProfiles() {
            System.out.println();
            System.out.println("Restricted Security Available Profiles' Info:");
            System.out.println("=============================================");

            Set<String> availableProfiles = new HashSet<>();
            Pattern profileNamePattern = Pattern.compile("^(RestrictedSecurity\\.\\S+)\\.desc\\.name");
            for(Object securityFileObject : securityProps.keySet()) {
                if (securityFileObject instanceof String) {
                    String key = (String) securityFileObject;
                    Matcher profileMatcher = profileNamePattern.matcher(key);
                    if (profileMatcher.matches()) {
                        availableProfiles.add(profileMatcher.group(1));
                    }
                }
            }
            System.out.println("The available Restricted Security profiles:\n");

            for (String availableProfile : availableProfiles) {
                printProfile(availableProfile);
            }
        }

        private void printProfile(String profileToPrint) {
            Set<String> propertyNames = securityProps.stringPropertyNames();
            List<String> descKeys = new ArrayList<>();
            List<String> providers = new ArrayList<>();
            List<String> restrictions = new ArrayList<>();
            for (String propertyName : propertyNames) {
                if (propertyName.startsWith(profileToPrint + ".desc.") || propertyName.startsWith(profileToPrint + ".fips.")) {
                    descKeys.add(propertyName + securityProps.getProperty(propertyName));
                } else if (propertyName.startsWith(profileToPrint + ".jce.provider.")) {
                    providers.add(propertyName + securityProps.getProperty(propertyName));
                } else if (propertyName.startsWith(profileToPrint)) {
                    restrictions.add(propertyName + securityProps.getProperty(propertyName));
                }
            }

            System.out.println(profileToPrint + " Profile Info:");
            System.out.println("==========================================");
            for (String descKey : descKeys) {
                System.out.println(descKey);
            }
            System.out.println();

            // List providers.
            System.out.println(profileToPrint + " Profile Providers:");
            System.out.println("===============================================");
            for (String provider : providers) {
                System.out.println(provider);
            }
            System.out.println();

            // List profile restrictions.
            System.out.println(profileToPrint + " Profile Restrictions:");
            System.out.println("==================================================");
            for (String restriction : restrictions) {
                System.out.println(restriction);
            }
            System.out.println();
        }

        /**
         * Only set a property if the value is not null.
         *
         * @param property      the property to be set
         * @param propertyKey   the property key in the java.security file
         * @return              whether the property was set
         */
        private boolean setProperty(String property, String propertyKey, List<String> allInfo) {
            if (debug != null) {
                debug.println("Setting property: " + property);
            }
            String value = securityProps.getProperty(propertyKey);
            value = parseProperty(value);
            String newValue = null;
            if (value != null) {
                // Add to info to create hash.
                allInfo.add(propertyKey + "=" + value);

                // Check if property overrides, adds to or removes from previous value.
                String existingValue = getExistingValue(property);
                if (value.startsWith("+")) {
                    if (!isPropertyAppendable(property)) {
                        printStackTraceAndExit("Property '" + property + "' is not appendable.");
                    } else {
                        // Append additional values to property.
                        value = value.substring(1).trim();

                        // Take existing value of property into account, if applicable.
                        if (existingValue == null) {
                            printStackTraceAndExit("Property '" + property + "' does not exist in"
                                    + " parent profile or java.security file. Cannot append.");
                        } else if (isBlank(existingValue)) {
                            newValue = value;
                        } else {
                            newValue = isBlank(value) ? existingValue : existingValue + ", " + value;
                        }
                    }
                } else if (value.startsWith("-")) {
                    if (!isPropertyAppendable(property)) {
                        printStackTraceAndExit("Property '" + property + "' is not appendable.");
                    } else {
                        // Remove values from property.
                        value = value.substring(1).trim();
                        if (!isBlank(value)) {
                            if (existingValue == null) {
                                printStackTraceAndExit("Property '" + property + "' does not exist in"
                                    + " parent profile or java.security file. Cannot remove.");
                            }
                            List<String> existingValues = Stream.of(existingValue.split(","))
                                                                .map(v -> v.trim())
                                                                .collect(Collectors.toList());
                            String[] valuesToRemove = value.split(",");
                            for (String valueToRemove : valuesToRemove) {
                                if (!existingValues.remove(valueToRemove.trim())) {
                                    printStackTraceAndExit("Value '" + valueToRemove + "' is not in existing values.");
                                }
                            }
                            newValue = String.join(",", existingValues);
                        } else {
                            // Nothing to do. Use existing value of property into account, if available.
                            if (existingValue == null) {
                                printStackTraceAndExit("Property '" + property + "' does not exist in"
                                    + " parent profile or java.security file. Cannot remove.");
                            } else if (isBlank(existingValue)) {
                                newValue = value;
                            } else {
                                newValue = existingValue;
                            }
                        }
                    }
                } else {
                    newValue = value;
                }
                profileProperties.put(property, newValue);
                profileCheckPropertyNames.remove(propertyKey);
                return true;
            }
            if (debug != null) {
                debug.println("Nothing to set. Value of property " + property + " is null.");
            }

            return false;
        }

        private String getProperty(String property) {
            return profileProperties.get(property);
        }

        private static boolean isPropertyAppendable(String property) {
            switch (property) {
            case "jdkCertpathDisabledAlgorithms":
            case "jdkSecurityLegacyAlgorithms":
            case "jdkTlsDisabledAlgorithms":
            case "jdkTlsDisabledNamedCurves":
            case "jdkTlsLegacyAlgorithms":
                return true;
            default:
                return false;
            }
        }

        /**
         * Trim input string if not null.
         *
         * @param string the input string
         * @return the string trimmed or null
         */
        private static String parseProperty(String string) {
            if (string != null) {
                string = string.trim();
            }

            return string;
        }

        private static void checkProviderFormat(String providerInfo, boolean update) {
            final String nameRE = "[A-Za-z0-9.-]+";
            final String fileRE = "[A-Za-z0-9./\\\\${}]+";
            Pattern p = Pattern.compile(
                  "^(" + nameRE + ")"                   // provider name
                + "\\s*"
                + "(" + fileRE + ")?"                   // configuration file [optional]
                + "\\s*"
                + "(\\["                                // constraints [optional]
                    + "\\s*"
                    + "([+-])?"                         // action [optional]
                    + "[A-Za-z0-9{}.=*|:,/_\\s-]+"      // constraint definition
                + "\\])?"
                + "\\s*"
                + "$");
            Matcher m = p.matcher(providerInfo);
            if (m.find()) {
                String providerName = m.group(1);
                if (providerName.indexOf('.') <= 0) {
                    printStackTraceAndExit("Provider must be specified using"
                            + " the fully-qualified class name: " + providerName);
                }

                String action = m.group(4);
                if (!update && !isNullOrBlank(action)) {
                    printStackTraceAndExit("You cannot add or remove to provider "
                            + m.group(1) + ". This is the base profile.");
                }
            } else {
                printStackTraceAndExit("Provider format is incorrect: " + providerInfo);
            }
        }

        private void loadProfileCheck(String profileID) {
            Enumeration<?> pNames = securityProps.propertyNames();
            String profileDot = profileID + '.';
            while (pNames.hasMoreElements()) {
                String name = (String) pNames.nextElement();
                if (name.startsWith(profileDot)) {
                    if (name.contains(".jce.provider.")) {
                        profileCheckProviderNames.add(name);
                    } else {
                        profileCheckPropertyNames.add(name);
                    }
                }
            }
        }

        private void checkProfileCheck(String profileID) {
            if (!profileCheckProviderNames.isEmpty()) {
                printStackTraceAndExit(
                        "The order numbers of providers in profile " + profileID
                                + " (or a base profile) are not consecutive.");
            }
            if (!profileCheckPropertyNames.isEmpty()) {
                printStackTraceAndExit(
                        "The property names: "
                                + profileCheckPropertyNames
                                        .stream()
                                        .sorted()
                                        .collect(Collectors.joining(", "))
                                + " in profile " + profileID
                                + " (or a base profile) are not recognized.");
            }
        }
    }

    /**
     * A class representing the constraints of a provider.
     */
    private static final class Constraint {
        final String type;
        final String algorithm;
        final String attributes;

        Constraint(String type, String algorithm, String attributes) {
            super();
            this.type = type;
            this.algorithm = algorithm;
            this.attributes = attributes;
        }

        @Override
        public String toString() {
            return "{" + type + ", " + algorithm + ", " + attributes + "}";
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof Constraint) {
                Constraint other = (Constraint) obj;
                return Objects.equals(type, other.type)
                    && Objects.equals(algorithm, other.algorithm)
                    && Objects.equals(attributes, other.attributes);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, algorithm, attributes);
        }
    }
}
