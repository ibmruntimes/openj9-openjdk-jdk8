/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2023 All Rights Reserved
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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider.Service;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sun.security.util.Debug;

/**
 * Configures the security providers when in restricted security mode.
 */
public final class RestrictedSecurity {

    private static final Debug debug = Debug.getInstance("semerufips");

    // Restricted security mode enable check, only supported on Linux x64.
    private static final boolean userEnabledFIPS;
    private static boolean isFIPSSupported;
    private static boolean isFIPSEnabled;

    private static final boolean isNSSSupported;
    private static final boolean isOpenJCEPlusSupported;

    private static final boolean userSetProfile;
    private static final boolean shouldEnableSecurity;
    private static String selectedProfile;
    private static String profileID;

    private static boolean securityEnabled;

    private static String userSecurityID;

    private static RestrictedSecurityProperties restricts;

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
                                System.getProperty("os.arch") };
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
            String providerName = providerClazz.getName();

            // Check if the specified class extends java.security.Provider.
            if (java.security.Provider.class.isAssignableFrom(providerClazz)) {
                return restricts.isRestrictedProviderAllowed(providerName);
            }

            // For a class that doesn't extend java.security.Provider, no need to
            // check allowed or not allowed, always return true to load it.
            if (debug != null) {
                debug.println("The provider class " + providerName + " does not extend java.security.Provider.");
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

        if (selectedProfile.indexOf(".") != -1) {
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
            for (Object keyObject : props.keySet()) {
                if (keyObject instanceof String) {
                    String key = (String) keyObject;
                    if (key.startsWith(potentialProfileID) && key.endsWith(".desc.default")) {
                        // Check if property is set to true.
                        if (Boolean.parseBoolean(props.getProperty(key))) {
                            // Check if multiple defaults exist and act accordingly.
                            if (defaultMatch == null) {
                                defaultMatch = key.split("\\.desc")[0];
                            } else {
                                printStackTraceAndExit("Multiple default RestrictedSecurity"
                                        + " profiles for " + selectedProfile);
                            }
                        }
                    }
                }
            }
            if (defaultMatch == null) {
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

    private static void checkFIPSCompatibility(Properties props) {
        boolean isFIPSProfile = Boolean.parseBoolean(props.getProperty(profileID + ".desc.fips"));
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

                // If user enabled FIPS, check whether chosen profile is applicable.
                if (userEnabledFIPS) {
                    checkFIPSCompatibility(props);
                }

                // Initialize restricted security properties from java.security file.
                restricts = new RestrictedSecurityProperties(profileID, props);

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
        propsMapping.put("jdk.tls.ephemeralDHKeySize", restricts.jdkTlsDphemeralDHKeySize);
        propsMapping.put("jdk.tls.legacyAlgorithms", restricts.jdkTlsLegacyAlgorithms);
        propsMapping.put("jdk.certpath.disabledAlgorithms", restricts.jdkCertpathDisabledAlgorithms);
        propsMapping.put("jdk.security.legacyAlgorithm", restricts.jdkSecurityLegacyAlgorithm);

        for (Map.Entry<String, String> entry : propsMapping.entrySet()) {
            String jdkPropsName = entry.getKey();
            String propsNewValue = entry.getValue();

            String propsOldValue = props.getProperty(jdkPropsName);
            if (isNullOrBlank(propsOldValue)) {
                propsOldValue = "";
            }

            if (!isNullOrBlank(propsNewValue)) {
                String values = isNullOrBlank(propsOldValue) ? propsNewValue : (propsOldValue + ", " + propsNewValue);
                props.setProperty(jdkPropsName, values);
                if (debug != null) {
                    debug.println("Added restricted security properties, with property: " + jdkPropsName + " value: "
                            + values);
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
    }

    /**
     * Check if restricted security policy is sunset.
     *
     * @param descSunsetDate the sunset date from java.security
     * @return true if restricted security policy sunset
     */
    private static boolean isPolicySunset(String descSunsetDate) {
        boolean isSunset = false;
        try {
            isSunset = LocalDate.parse(descSunsetDate, DateTimeFormatter.ofPattern("yyyy-MM-dd"))
                    .isBefore(LocalDate.now());
        } catch (DateTimeParseException except) {
            printStackTraceAndExit(
                    "Restricted security policy sunset date is incorrect, the correct format is yyyy-MM-dd.");
        }

        if (debug != null) {
            debug.println("Restricted security policy is sunset: " + isSunset);
        }
        return isSunset;
    }

    /**
     * Check if the input string is null or blank.
     *
     * @param string the input string
     * @return true if the input string is null or blank
     */
    private static boolean isNullOrBlank(String string) {
        return (string == null) || string.trim().isEmpty();
    }

    private static void printStackTraceAndExit(Exception exception) {
        exception.printStackTrace();
        System.exit(1);
    }

    private static void printStackTraceAndExit(String message) {
        printStackTraceAndExit(new RuntimeException(message));
    }

    /**
     * This class is used to save and operate on restricted security
     * properties which are loaded from the java.security file.
     */
    private static final class RestrictedSecurityProperties {

        private String descName;
        private boolean descIsDefault;
        private boolean descIsFIPS;
        private String descNumber;
        private String descPolicy;
        private String descSunsetDate;

        // Security properties.
        private String jdkTlsDisabledNamedCurves;
        private String jdkTlsDisabledAlgorithms;
        private String jdkTlsDphemeralDHKeySize;
        private String jdkTlsLegacyAlgorithms;
        private String jdkCertpathDisabledAlgorithms;
        private String jdkSecurityLegacyAlgorithm;
        private String keyStoreType;
        private String keyStore;

        // For SecureRandom.
        String jdkSecureRandomAlgorithm;

        // Provider with argument (provider name + optional argument).
        private final List<String> providers;
        // Provider without argument.
        private final List<String> providersSimpleName;
        // The map is keyed by provider name.
        private final Map<String, Constraint[]> providerConstraints;

        private final String profileID;

        // The java.security properties.
        private final Properties securityProps;

        /**
         *
         * @param id    the restricted security custom profile ID
         * @param props the java.security properties
         * @param trace the user security trace
         * @param audit the user security audit
         * @param help  the user security help
         */
        private RestrictedSecurityProperties(String id, Properties props) {
            Objects.requireNonNull(props);

            profileID = id;
            securityProps = props;

            providers = new ArrayList<>();
            providersSimpleName = new ArrayList<>();
            providerConstraints = new HashMap<>();

            // Initialize the properties.
            init();
        }

        /**
         * Initialize restricted security properties.
         */
        private void init() {
            if (debug != null) {
                debug.println("Initializing restricted security mode.");
            }

            try {
                // Load restricted security providers from java.security properties.
                initProviders();
                // Load restricted security properties from java.security properties.
                initProperties();
                // Load restricted security provider constraints from java.security properties.
                initConstraints();
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Unable to initialize restricted security mode.");
                }
                printStackTraceAndExit(e);
            }

            if (debug != null) {
                debug.println("Initialization of restricted security mode completed.");

                // Print all available restricted security profiles.
                listAvailableProfiles();

                // Print information of utilized security profile.
                listUsedProfile();
            }
        }

        /**
         * Load restricted security provider.
         */
        private void initProviders() {
            if (debug != null) {
                debug.println("\tLoading providers of restricted security profile.");
            }

            for (int pNum = 1;; ++pNum) {
                String providerInfo = securityProps
                        .getProperty(profileID + ".jce.provider." + pNum);

                if ((providerInfo == null) || providerInfo.trim().isEmpty()) {
                    break;
                }

                if (!areBracketsBalanced(providerInfo)) {
                    printStackTraceAndExit("Provider format is incorrect: " + providerInfo);
                }

                int pos = providerInfo.indexOf('[');
                String providerName = (pos < 0) ? providerInfo.trim() : providerInfo.substring(0, pos).trim();
                // Provider with argument (provider name + optional argument).
                providers.add(pNum - 1, providerName);

                // Provider name defined in provider construction method.
                providerName = getProvidersSimpleName(providerName);
                providersSimpleName.add(pNum - 1, providerName);
            }

            if (providers.isEmpty()) {
                printStackTraceAndExit(
                        "No providers are specified as part of the Restricted Security profile.");
            }

            if (debug != null) {
                debug.println("\tProviders of restricted security profile successfully loaded.");
            }
        }

        /**
         * Load restricted security properties.
         */
        private void initProperties() {
            if (debug != null) {
                debug.println("\tLoading properties of restricted security profile.");
            }

            descName = parseProperty(securityProps.getProperty(profileID + ".desc.name"));
            descIsDefault = Boolean.parseBoolean(parseProperty(securityProps.getProperty(profileID + ".desc.default")));
            descIsFIPS = Boolean.parseBoolean(parseProperty(securityProps.getProperty(profileID + ".desc.fips")));
            descNumber = parseProperty(securityProps.getProperty(profileID + ".desc.number"));
            descPolicy = parseProperty(securityProps.getProperty(profileID + ".desc.policy"));
            descSunsetDate = parseProperty(securityProps.getProperty(profileID + ".desc.sunsetDate"));

            jdkTlsDisabledNamedCurves = parseProperty(
                    securityProps.getProperty(profileID + ".tls.disabledNamedCurves"));
            jdkTlsDisabledAlgorithms = parseProperty(
                    securityProps.getProperty(profileID + ".tls.disabledAlgorithms"));
            jdkTlsDphemeralDHKeySize = parseProperty(
                    securityProps.getProperty(profileID + ".tls.ephemeralDHKeySize"));
            jdkTlsLegacyAlgorithms = parseProperty(
                    securityProps.getProperty(profileID + ".tls.legacyAlgorithms"));
            jdkCertpathDisabledAlgorithms = parseProperty(
                    securityProps.getProperty(profileID + ".jce.certpath.disabledAlgorithms"));
            jdkSecurityLegacyAlgorithm = parseProperty(
                    securityProps.getProperty(profileID + ".jce.legacyAlgorithms"));
            keyStoreType = parseProperty(
                    securityProps.getProperty(profileID + ".keystore.type"));
            keyStore = parseProperty(
                    securityProps.getProperty(profileID + ".javax.net.ssl.keyStore"));

            jdkSecureRandomAlgorithm = parseProperty(
                    securityProps.getProperty(profileID + ".securerandom.algorithm"));

            if (debug != null) {
                debug.println("\tProperties of restricted security profile successfully loaded.");
            }
        }

        /**
         * Load security constraints with type, algorithm, attributes.
         *
         * Example:
         * RestrictedSecurity1.jce.provider.1 = SUN [{CertPathBuilder, PKIX, *},
         * {Policy, JavaPolicy, *}, {CertPathValidator, *, *}].
         */
        private void initConstraints() {
            if (debug != null) {
                debug.println("\tLoading constraints of restricted security profile.");
            }

            for (int pNum = 1; pNum <= providersSimpleName.size(); pNum++) {
                String providerName = providersSimpleName.get(pNum - 1);
                String providerInfo = securityProps
                        .getProperty(profileID + ".jce.provider." + pNum);

                if (debug != null) {
                    debug.println("\t\tLoading constraints for security provider: " + providerName);
                }

                // Check if the provider has constraints.
                if (providerInfo.indexOf('[') < 0) {
                    if (debug != null) {
                        debug.println("\t\t\tNo constraints for security provider: " + providerName);
                    }
                    providerConstraints.put(providerName, new Constraint[0]);
                    continue;
                }

                // Remove the whitespaces in the format separator if present.
                providerInfo = providerInfo.trim()
                        .replaceAll("\\[\\s+\\{", "[{")
                        .replaceAll("\\}\\s+\\]", "}]")
                        .replaceAll("\\}\\s*,\\s*\\{", "},{");

                int startIndex = providerInfo.lastIndexOf("[{");
                int endIndex = providerInfo.indexOf("}]");

                // Provider with constraints.
                if ((startIndex > 0) && (endIndex > startIndex)) {
                    String[] constrArray = providerInfo
                            .substring(startIndex + 2, endIndex).split("\\},\\{");

                    if (constrArray.length <= 0) {
                        printStackTraceAndExit("Constraint format is incorrect: " + providerInfo);
                    }

                    // Constraint object array.
                    // For each constraint type, algorithm and attributes.
                    Constraint[] constraints = new Constraint[constrArray.length];

                    int cNum = 0;
                    for (String constr : constrArray) {
                        String[] input = constr.split(",");

                        // Each constraint must includes 3 fields(type, algorithm, attributes).
                        if (input.length != 3) {
                            printStackTraceAndExit("Constraint format is incorrect: " + providerInfo);
                        }

                        String inType = input[0].trim();
                        String inAlgorithm = input[1].trim();
                        String inAttributes = input[2].trim();

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

                        if (debug != null) {
                            debug.println("\t\t\tConstraint specified for security provider: " + providerName);
                            debug.println("\t\t\t\twith type: " + inType);
                            debug.println("\t\t\t\tfor algorithm: " + inAlgorithm);
                            debug.println("\t\t\t\twith attributes: " + inAttributes);
                        }
                        constraints[cNum] = constraint;
                        cNum++;
                    }
                    providerConstraints.put(providerName, constraints);
                    if (debug != null) {
                        debug.println("\t\tSuccessfully loaded constraints for security provider: " + providerName);
                    }
                } else {
                    printStackTraceAndExit("Constraint format is incorrect: " + providerInfo);
                }
            }

            if (debug != null) {
                debug.println("\tAll constraints of restricted security profile successfully loaded.");
            }
        }

        /**
         * Check if the Service is allowed in restricted security mode.
         *
         * @param service the Service to check
         * @return true if the Service is allowed
         */
        boolean isRestrictedServiceAllowed(Service service) {
            String providerName = service.getProvider().getName();

            // Provider with argument, remove argument.
            // e.g. SunPKCS11-NSS-FIPS, remove argument -NSS-FIPS.
            int pos = providerName.indexOf('-');
            providerName = (pos < 0) ? providerName : providerName.substring(0, pos);

            Constraint[] constraints = providerConstraints.get(providerName);

            if (constraints == null) {
                // Disallow unknown providers.
                return false;
            } else if (constraints.length == 0) {
                // Allow this provider with no constraints.
                return true;
            }

            // Check the constraints of this provider.
            String type = service.getType();
            String algorithm = service.getAlgorithm();

            for (Constraint constraint : constraints) {
                String cType = constraint.type;
                String cAlgorithm = constraint.algorithm;
                String cAttribute = constraint.attributes;

                if (!isAsterisk(cType) && !type.equalsIgnoreCase(cType)) {
                    // The constraint doesn't apply to the service type.
                    continue;
                }
                if (!isAsterisk(cAlgorithm) && !algorithm.equals(cAlgorithm)) {
                    // The constraint doesn't apply to the service algorithm.
                    continue;
                }

                // For type and algorithm match, and attribute is *.
                if (isAsterisk(cAttribute)) {
                    if (debug != null) {
                        debug.println("Security constraints check."
                                + " Service type: " + type
                                + " Algorithm: " + algorithm
                                + " is allowed in provider: " + providerName);
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
                    if ((sValue == null) || !cValue.equalsIgnoreCase(sValue)) {
                        // If any attribute doesn't match, return service is not allowed.
                        if (debug != null) {
                            debug.println(
                                    "Security constraints check."
                                            + " Service type: " + type
                                            + " Algorithm: " + algorithm
                                            + " Attribute: " + cAttribute
                                            + " is NOT allowed in provider: " + providerName);
                        }
                        return false;
                    }
                }
                if (debug != null) {
                    debug.println(
                            "Security constraints check."
                                    + " Service type: " + type
                                    + " Algorithm: " + algorithm
                                    + " Attribute: " + cAttribute
                                    + " is allowed in provider: " + providerName);
                }
                return true;
            }
            if (debug != null) {
                debug.println("Security constraints check."
                        + " Service type: " + type
                        + " Algorithm: " + algorithm
                        + " is NOT allowed in provider: " + providerName);
            }
            // No match for any constraint, return NOT allowed.
            return false;
        }

        /**
         * Check if the provider is allowed in restricted security mode.
         *
         * @param providerName the provider to check
         * @return true if the provider is allowed
         */
        boolean isRestrictedProviderAllowed(String providerName) {
            if (debug != null) {
                debug.println("Checking the provider " + providerName + " in restricted security mode.");
            }

            providerName = getProvidersSimpleName(providerName);

            // Check if the provider is in restricted security provider list.
            // If not, the provider won't be registered.
            if (providersSimpleName.contains(providerName)) {
                if (debug != null) {
                    debug.println("The provider " + providerName + " is allowed in restricted security mode.");
                }
                return true;
            }

            if (debug != null) {
                debug.println("The provider " + providerName + " is not allowed in restricted security mode.");

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
         * Get the provider name defined in provider construction method.
         *
         * @param providerName provider name or provider with packages or arguments
         * @return provider name defined in provider construction method
         */
        private static String getProvidersSimpleName(String providerName) {
            // Remove the provider's optional arguments if present.
            int pos = providerName.indexOf(' ');
            providerName = (pos < 0) ? providerName.trim() : providerName.substring(0, pos).trim();

            // Remove argument, e.g. -NSS-FIPS, if present.
            pos = providerName.indexOf('-');
            providerName = (pos < 0) ? providerName : providerName.substring(0, pos);

            if (providerName.equals("com.sun.net.ssl.internal.ssl.Provider")) {
                // In JDK 8, the main class for the SunJSSE provider is
                // com.sun.net.ssl.internal.ssl.Provider
                return "SunJSSE";
            } else if (providerName.equals("sun.security.provider.Sun")) {
                // In JDK 8, the main class for the SUN provider is sun.security.provider.Sun
                return "SUN";
            } else {
                // Remove the provider's class package names if present.
                pos = providerName.lastIndexOf('.');
                providerName = (pos < 0) ? providerName : providerName.substring(pos + 1);
                // Provider without arguments and package names.
                return providerName;
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

        /**
         * List the RestrictedSecurity profile currently used.
         */
        private void listUsedProfile() {
            System.out.println();
            System.out.println("Utilized Restricted Security Profile Info:");
            System.out.println("==========================================");
            System.out.println("The Restricted Security profile used is: " + profileID);
            System.out.println();
            printProfile(profileID);
        }

        private void printProfile(String profileToPrint) {
            System.out.println(profileToPrint + " Profile Info:");
            System.out.println("==========================================");
            printProperty(profileToPrint + ".desc.name: ",
                    securityProps.getProperty(profileToPrint + ".desc.name"));
            printProperty(profileToPrint + ".desc.default: ",
                    securityProps.getProperty(profileToPrint + ".desc.default"));
            printProperty(profileToPrint + ".desc.fips: ",
                    securityProps.getProperty(profileToPrint + ".desc.fips"));
            printProperty(profileToPrint + ".desc.number: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".desc.number")));
            printProperty(profileToPrint + ".desc.policy: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".desc.policy")));
            printProperty(profileToPrint + ".desc.sunsetDate: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".desc.sunsetDate")));
            System.out.println();

            // List providers.
            System.out.println(profileToPrint + " Profile Providers:");
            System.out.println("===============================================");
            for (int pNum = 1;; ++pNum) {
            String providerInfo = securityProps
                    .getProperty(profileToPrint + ".jce.provider." + pNum);

                if ((providerInfo == null) || providerInfo.trim().isEmpty()) {
                    break;
                }
                printProperty(profileToPrint + ".jce.provider." + pNum + ": ", providerInfo);
            }
            System.out.println();

            // List profile restrictions.
            System.out.println(profileToPrint + " Profile Restrictions:");
            System.out.println("==================================================");
            printProperty(profileToPrint + ".tls.disabledNamedCurves: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".tls.disabledNamedCurves")));
            printProperty(profileToPrint + ".tls.disabledAlgorithms: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".tls.disabledAlgorithms")));
            printProperty(profileToPrint + ".tls.ephemeralDHKeySize: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".tls.ephemeralDHKeySize")));
            printProperty(profileToPrint + ".tls.legacyAlgorithms: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".tls.legacyAlgorithms")));
            printProperty(profileToPrint + ".jce.certpath.disabledAlgorithms: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".jce.certpath.disabledAlgorithms")));
            printProperty(profileToPrint + ".jce.legacyAlgorithms: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".jce.legacyAlgorithms")));
            System.out.println();

            printProperty(profileToPrint + ".keystore.type: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".keystore.type")));
            printProperty(profileToPrint + ".javax.net.ssl.keyStore: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".javax.net.ssl.keyStore")));
            printProperty(profileToPrint + ".securerandom.provider: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".securerandom.provider")));
            printProperty(profileToPrint + ".securerandom.algorithm: ",
                    parseProperty(securityProps.getProperty(profileToPrint + ".securerandom.algorithm")));
            System.out.println();
        }

        private void printProperty(String name, String value) {
            String valueToPrint = (value.isEmpty()) ? "NOT AVAILABLE" : value;
            System.out.println(name + valueToPrint);
        }

        /**
         * Check if the input string is null. If null return "".
         *
         * @param string the input string
         * @return "" if the string is null
         */
        private static String parseProperty(String string) {
            return (string != null) ? string.trim() : "";
        }

        /**
         * Check if the brackets are balanced.
         *
         * @param string input string for checking
         * @return true if the brackets are balanced
         */
        private static boolean areBracketsBalanced(String string) {
            Deque<Character> deque = new LinkedList<>();

            for (char ch : string.toCharArray()) {
                switch (ch) {
                case '{':
                    deque.addFirst('}');
                    break;
                case '[':
                    deque.addFirst(']');
                    break;
                case '(':
                    deque.addFirst(')');
                    break;
                case '}':
                case ']':
                case ')':
                    if (deque.isEmpty() || (deque.removeFirst().charValue() != ch)) {
                        return false;
                    }
                    break;
                default:
                    break;
                }
            }
            return deque.isEmpty();
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
        }
    }
}
