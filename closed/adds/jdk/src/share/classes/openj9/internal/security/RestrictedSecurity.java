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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import sun.security.util.Debug;

/**
 * Configures the security providers when in restricted security mode.
 */
public final class RestrictedSecurity {

    private static final Debug debug = Debug.getInstance("semerufips");

    // Restricted security mode enable check, only supported on Linux x64.
    private static final boolean userEnabledFIPS;
    private static final boolean userEnabledSecurity;
    private static final boolean isSecuritySupported;
    private static final boolean shouldEnableSecurity;
    private static final String userSecuritySetting;

    private static boolean securityEnabled;

    private static int userSecurityNum;
    private static boolean userSecurityTrace;
    private static boolean userSecurityAudit;
    private static boolean userSecurityHelp;

    private static RestrictedSecurityProperties restricts;

    private static final List<String> supportPlatforms = Arrays.asList("amd64", "ppc64le", "s390x");

    static {
        @SuppressWarnings("removal")
        String[] props = AccessController.doPrivileged(
                new PrivilegedAction<String[]>() {
                    @Override
                    public String[] run() {
                        return new String[] { System.getProperty("semeru.fips"),
                                System.getProperty("semeru.restrictedsecurity"),
                                System.getProperty("os.name"),
                                System.getProperty("os.arch") };
                    }
                });
        userEnabledFIPS = Boolean.parseBoolean(props[0]);
        // If semeru.fips is true, then ignore semeru.restrictedsecurity, use userSecurityNum 1.
        userSecuritySetting = userEnabledFIPS ? "1" : props[1];
        userEnabledSecurity = !isNullOrBlank(userSecuritySetting);
        isSecuritySupported = "Linux".equalsIgnoreCase(props[2])
                && supportPlatforms.contains(props[3]);
        shouldEnableSecurity = (userEnabledFIPS || userEnabledSecurity) && isSecuritySupported;
    }

    private RestrictedSecurity() {
        super();
    }

    /**
     * Check if restricted security mode is enabled.
     *
     * Restricted security mode is enabled when, on supported platforms,
     * the semeru.restrictedsecurity system property is set or the system
     * property semeru.fips is true.
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
     * FIPS mode will be enabled when the semeru.fips system property is true,
     * or semeru.restrictedsecurity system property is set by using FIPS policy.
     *
     * @return true if FIPS is enabled
     */
    public static boolean isFIPSEnabled() {
        return securityEnabled && (userSecurityNum == 1);
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

        // Check if restricted security is supported on this platform.
        if ((userEnabledFIPS || userEnabledSecurity) && !isSecuritySupported) {
            printStackTraceAndExit("Restricted security mode is not supported on this platform.");
        }

        try {
            if (shouldEnableSecurity) {
                if (debug != null) {
                    debug.println("Restricted security mode detected, loading...");
                }

                // Read and set user restricted security settings.
                initUserSetting();

                // Initialize restricted security properties from java.security file.
                restricts = new RestrictedSecurityProperties(userSecurityNum,
                        props, userSecurityTrace, userSecurityAudit, userSecurityHelp);

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

                // Print out the Trace info.
                if (userSecurityTrace) {
                    restricts.listTrace();
                }

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
     * Load user restricted security settings from system property.
     */
    private static void initUserSetting() {
        if (debug != null) {
            debug.println("Loading user restricted security settings.");
        }

        String[] inputs = userSecuritySetting.split(",");

        // For input ",,"
        if (inputs.length == 0) {
            printStackTraceAndExit("User restricted security setting " + userSecuritySetting + " incorrect.");
        }

        for (String input : inputs) {
            String in = input.trim();
            if (in.equalsIgnoreCase("audit")) {
                userSecurityAudit = true;
            } else if (in.equalsIgnoreCase("help")) {
                userSecurityHelp = true;
            } else if (in.equalsIgnoreCase("trace")) {
                userSecurityTrace = true;
            } else {
                try {
                    userSecurityNum = Integer.parseInt(in);
                } catch (NumberFormatException e) {
                    printStackTraceAndExit("User restricted security setting " + userSecuritySetting + " incorrect.");
                }
            }
        }

        if (debug != null) {
            debug.println("Loaded user restricted security settings, with userSecurityNum: " + userSecurityNum
                    + " userSecurityTrace: " + userSecurityTrace
                    + " userSecurityAudit: " + userSecurityAudit
                    + " userSecurityHelp: " + userSecurityHelp);
        }
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

        private final int userSecurityNum;
        private final boolean userSecurityTrace;
        private final boolean userSecurityAudit;
        private final boolean userSecurityHelp;

        private final String propsPrefix;

        // The java.security properties.
        private final Properties securityProps;

        /**
         *
         * @param num   the restricted security setting number
         * @param props the java.security properties
         * @param trace the user security trace
         * @param audit the user security audit
         * @param help  the user security help
         */
        private RestrictedSecurityProperties(int num, Properties props, boolean trace, boolean audit, boolean help) {
            Objects.requireNonNull(props);

            userSecurityNum = num;
            userSecurityTrace = trace;
            userSecurityAudit = audit;
            userSecurityHelp = help;
            securityProps = props;

            propsPrefix = "RestrictedSecurity" + userSecurityNum;

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
                // Print out the Help and Audit info.
                if (userSecurityHelp || userSecurityAudit || userSecurityTrace) {
                    if (userSecurityHelp) {
                        printHelp();
                    }
                    if (userSecurityAudit) {
                        listAudit();
                    }
                    if (userSecurityNum == 0) {
                        if (userSecurityTrace) {
                            printStackTraceAndExit(
                                    "Unable to list the trace info without specify the security policy number.");
                        } else {
                            if (debug != null) {
                                debug.println("Print out the info and exit.");
                            }
                            System.exit(0);
                        }
                    }
                }

                // Load restricted security providers from java.security properties.
                initProviders();
                // Load restricted security properties from java.security properties.
                initProperties();
                // Load restricted security provider constraints from java.security properties.
                initConstraints();

                if (debug != null) {
                    debug.println("Initialized restricted security mode.");
                }
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Unable to initialize restricted security mode.");
                }
                printStackTraceAndExit(e);
            }
        }

        /**
         * Load restricted security provider.
         */
        private void initProviders() {
            if (debug != null) {
                debug.println("Loading restricted security providers.");
            }

            for (int pNum = 1;; ++pNum) {
                String providerInfo = securityProps
                        .getProperty(propsPrefix + ".jce.provider." + pNum);

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

                if (debug != null) {
                    debug.println(
                            "Loaded restricted security provider: " + providers.get(pNum - 1)
                                    + " with simple name: " + providerName);
                }
            }

            if (providers.isEmpty()) {
                printStackTraceAndExit(
                        "Restricted security mode provider list empty, or no such restricted security policy in java.security file.");
            }
        }

        /**
         * Load restricted security properties.
         */
        private void initProperties() {
            if (debug != null) {
                debug.println("Loading restricted security properties.");
            }

            descName = parseProperty(securityProps.getProperty(propsPrefix + ".desc.name"));
            descNumber = parseProperty(securityProps.getProperty(propsPrefix + ".desc.number"));
            descPolicy = parseProperty(securityProps.getProperty(propsPrefix + ".desc.policy"));
            descSunsetDate = parseProperty(securityProps.getProperty(propsPrefix + ".desc.sunsetDate"));

            jdkTlsDisabledNamedCurves = parseProperty(
                    securityProps.getProperty(propsPrefix + ".tls.disabledNamedCurves"));
            jdkTlsDisabledAlgorithms = parseProperty(
                    securityProps.getProperty(propsPrefix + ".tls.disabledAlgorithms"));
            jdkTlsDphemeralDHKeySize = parseProperty(
                    securityProps.getProperty(propsPrefix + ".tls.ephemeralDHKeySize"));
            jdkTlsLegacyAlgorithms = parseProperty(
                    securityProps.getProperty(propsPrefix + ".tls.legacyAlgorithms"));
            jdkCertpathDisabledAlgorithms = parseProperty(
                    securityProps.getProperty(propsPrefix + ".jce.certpath.disabledAlgorithms"));
            jdkSecurityLegacyAlgorithm = parseProperty(
                    securityProps.getProperty(propsPrefix + ".jce.legacyAlgorithms"));
            keyStoreType = parseProperty(
                    securityProps.getProperty(propsPrefix + ".keystore.type"));
            keyStore = parseProperty(
                    securityProps.getProperty(propsPrefix + ".javax.net.ssl.keyStore"));

            jdkSecureRandomAlgorithm = parseProperty(
                    securityProps.getProperty(propsPrefix + ".securerandom.algorithm"));

            if (debug != null) {
                debug.println("Loaded restricted security properties.");
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
            for (int pNum = 1; pNum <= providersSimpleName.size(); pNum++) {
                String providerName = providersSimpleName.get(pNum - 1);
                String providerInfo = securityProps
                        .getProperty(propsPrefix + ".jce.provider." + pNum);

                if (debug != null) {
                    debug.println("Loading constraints for security provider: " + providerName);
                }

                // Check if the provider has constraints.
                if (providerInfo.indexOf('[') < 0) {
                    if (debug != null) {
                        debug.println("No constraints for security provider: " + providerName);
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
                            debug.println("Loading constraints for security provider: " + providerName
                                    + " with constraints type: " + inType
                                    + " algorithm: " + inAlgorithm
                                    + " attributes: " + inAttributes);
                        }
                        constraints[cNum] = constraint;
                        cNum++;
                    }
                    providerConstraints.put(providerName, constraints);
                    if (debug != null) {
                        debug.println("Loaded constraints for security provider: " + providerName);
                    }
                } else {
                    printStackTraceAndExit("Constraint format is incorrect: " + providerInfo);
                }
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
         * List audit info if userSecurityAudit is true, default as false.
         */
        private void listAudit() {
            System.out.println();
            System.out.println("Restricted Security Audit Info:");
            System.out.println("===============================");

            for (int num = 1;; ++num) {
                String desc = securityProps.getProperty("RestrictedSecurity" + num + ".desc.name");
                if ((desc == null) || desc.trim().isEmpty()) {
                    break;
                }
                System.out.println("RestrictedSecurity" + num + ".desc.name: "
                        + securityProps.getProperty("RestrictedSecurity" + num + ".desc.name"));
                System.out.println("RestrictedSecurity" + num + ".desc.number: "
                        + parseProperty(securityProps.getProperty("RestrictedSecurity" + num + ".desc.number")));
                System.out.println("RestrictedSecurity" + num + ".desc.policy: "
                        + parseProperty(securityProps.getProperty("RestrictedSecurity" + num + ".desc.policy")));
                System.out.println("RestrictedSecurity" + num + ".desc.sunsetDate: "
                        + parseProperty(securityProps.getProperty("RestrictedSecurity" + num + ".desc.sunsetDate")));
                System.out.println();
            }
        }

        /**
         * List trace info if userSecurityTrace is true, default as false.
         */
        void listTrace() {
            System.out.println();
            System.out.println("Restricted Security Trace Info:");
            System.out.println("===============================");
            System.out.println(propsPrefix + ".desc.name: " + descName);
            System.out.println(propsPrefix + ".desc.number: " + descNumber);
            System.out.println(propsPrefix + ".desc.policy: " + descPolicy);
            System.out.println(propsPrefix + ".desc.sunsetDate: " + descSunsetDate);
            System.out.println();

            // List restrictions.
            System.out.println(propsPrefix + ".tls.disabledNamedCurves: "
                    + parseProperty(securityProps.getProperty("jdk.tls.disabledNamedCurves")));
            System.out.println(propsPrefix + ".tls.disabledAlgorithms: "
                    + parseProperty(securityProps.getProperty("jdk.tls.disabledAlgorithms")));
            System.out.println(propsPrefix + ".tls.ephemeralDHKeySize: "
                    + parseProperty(securityProps.getProperty("jdk.tls.ephemeralDHKeySize")));
            System.out.println(propsPrefix + ".tls.legacyAlgorithms: "
                    + parseProperty(securityProps.getProperty("jdk.tls.legacyAlgorithms")));
            System.out.println(propsPrefix + ".jce.certpath.disabledAlgorithms: "
                    + parseProperty(securityProps.getProperty("jdk.certpath.disabledAlgorithms")));
            System.out.println(propsPrefix + ".jce.legacyAlgorithms: "
                    + parseProperty(securityProps.getProperty("jdk.security.legacyAlgorithm")));
            System.out.println();

            System.out.println(propsPrefix + ".keystore.type: "
                    + parseProperty(securityProps.getProperty("keystore.type")));
            System.out.println(propsPrefix + ".javax.net.ssl.keyStore: "
                    + keyStore);
            System.out.println(propsPrefix + ".securerandom.algorithm: "
                    + jdkSecureRandomAlgorithm);

            // List providers.
            System.out.println();
            for (int pNum = 1; pNum <= providers.size(); pNum++) {
                System.out.println(propsPrefix + ".jce.provider." + pNum + ": "
                        + providers.get(pNum - 1));
            }

            System.out.println();
        }

        /**
         * Print help info if userSecurityHelp is ture, default as false.
         */
        private void printHelp() {
            System.out.println();
            System.out.println("Restricted Security Mode Usage:");
            System.out.println("===============================");

            System.out.println(
                    "-Dsemeru.restrictedsecurity=<n>  This flag will select the settings for the user " +
                            "specified restricted security policy.");
            System.out.println(
                    "-Dsemeru.restrictedsecurity=audit  This flag will list the name and number of all " +
                            "configured restricted security policies.");
            System.out.println(
                    "-Dsemeru.restrictedsecurity=trace  This flag will list all properties relevant to " +
                            "restricted security mode, including the existing default properties and " +
                            "restricted security properties.");
            System.out.println("-Dsemeru.restrictedsecurity=help  This flag will print help message.");

            System.out.println();
            System.out.println("e.g.");
            System.out.println("    -Dsemeru.restrictedsecurity=1,trace,audit,help");
            System.out.println("    -Dsemeru.restrictedsecurity=help");

            System.out.println();
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
