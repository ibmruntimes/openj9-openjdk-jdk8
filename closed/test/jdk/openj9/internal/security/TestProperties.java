/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2025 All Rights Reserved
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

/*
 * @test
 * @summary Test Restricted Security Mode Properties
 * @library /jdk/test/lib/testlibrary
 * @run junit TestProperties
 */

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jdk.testlibrary.OutputAnalyzer;
import jdk.testlibrary.ProcessTools;

@RunWith(Parameterized.class)
public class TestProperties {

    private String customprofile;
    private String securityPropertyFile;
    private String securityPropertyFileList;
    private String expected;
    private int expectedExitValue;

    public TestProperties(String customprofile, String securityPropertyFile, String securityPropertyFileList, String expected, int expectedExitValue) {
        this.customprofile = customprofile;
        this.securityPropertyFile = securityPropertyFile;
        this.securityPropertyFileList = securityPropertyFileList;
        this.expected = expected;
        this.expectedExitValue = expectedExitValue;
    }

    @Parameters
    public static List<Object[]> data() {
        return Arrays.asList(new Object[][] {
            // 1 - Test property - Same beginnings of the profile name without version.
            {"Test-Profile-SameStartWithoutVersion",
                System.getProperty("test.src") + "/property-java.security", null,
                "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunJSSE)", 0},

            // 1 - Test profile - base profile misspell properties.
            {"Test-Profile.Base",
                System.getProperty("test.src") + "/property-java.security", null,
                "The property names: RestrictedSecurity.Test-Profile.Base.tls.disabledAlgorithmsWrongTypo "
                    + "in profile RestrictedSecurity.Test-Profile.Base \\(or a base profile\\) are not recognized", 1},
            // 2 - Test profile - extenstion profile misspell properties.
            {"Test-Profile.Extended_1",
                System.getProperty("test.src") + "/property-java.security", null,
                "The property names: RestrictedSecurity.Test-Profile.Extended_1.desc.nameWrongTypo, "
                    + "RestrictedSecurity.Test-Profile.Extended_1.jce.providerWrongTypo in profile "
                    + "RestrictedSecurity.Test-Profile.Extended_1 \\(or a base profile\\) are not recognized", 1},
            // 3 - Test profile - extension profile from another extension profile misspell properties.
            {"Test-Profile.Extended_2",
                System.getProperty("test.src") + "/property-java.security", null,
                "The property names: RestrictedSecurity.Test-Profile.Extended_2.jce.providerWrongTypo "
                    + "in profile RestrictedSecurity.Test-Profile.Extended_2 \\(or a base profile\\) are not recognized", 1},
            // 4 - Test profile - profile not exist.
            {"Test-Profile-NotExist.Base",
                System.getProperty("test.src") + "/property-java.security", null,
                "Test-Profile-NotExist.Base is not present in the java.security file.", 1},
            // 5 - Test profile - Multi Default profile.
            {"Test-Profile-MultiDefault",
                System.getProperty("test.src") + "/property-java.security", null,
                "Multiple default RestrictedSecurity profiles for Test-Profile-MultiDefault", 1},
            // 6 - Test profile - no default profile.
            {"Test-Profile-NoDefault",
                System.getProperty("test.src") + "/property-java.security", null,
                "No default RestrictedSecurity profile was found for Test-Profile-NoDefault", 1},
            // 7 - Test profile - base profile does not exist.
            {"Test-Profile.Extended_3",
                System.getProperty("test.src") + "/property-java.security", null,
                "RestrictedSecurity.Test-Profile.BaseNotExist that is supposed to extend \\'RestrictedSecurity.Test-Profile.Extended_3\\' "
                    + "is not present in the java.security file or any appended files", 1},
            // 8 - Test profile - base profile not full profile name.
            {"Test-Profile.Extended_4",
                System.getProperty("test.src") + "/property-java.security", null,
                "RestrictedSecurity.BaseNotFullProfileName that is supposed to extend \\'RestrictedSecurity.Test-Profile.Extended_4\\' "
                    + "is not a full profile name", 1},
            // 9 - Test profile - base profile without hash value.
            {"Test-Profile-BaseWithoutHash",
                System.getProperty("test.src") + "/property-java.security", null,
                "Test-Profile-BaseWithoutHash is a base profile, so a hash value is mandatory", 1},
            // 10 - Test profile - incorrect definition of hash value.
            {"Test-Profile-Hash_1",
                System.getProperty("test.src") + "/property-java.security", null,
                "Incorrect definition of hash value for RestrictedSecurity.Test-Profile-Hash_1", 1},
            // 11 - Test profile - incorrect hash value.
            {"Test-Profile-Hash_2",
                System.getProperty("test.src") + "/property-java.security", null,
                "Hex produced from profile is not the same is a base profile, so a hash value is mandatory", 1},
            // 12 - Test property - property not appendable.
            {"Test-Profile-SetProperty.Extension_1",
                System.getProperty("test.src") + "/property-java.security", null,
                "Property \\'jdkSecureRandomAlgorithm\\' is not appendable", 1},
            // 13 - Test property - property does not exist in parent profile, cannot append.
            {"Test-Profile-SetProperty.Extension_2",
                System.getProperty("test.src") + "/property-java.security", null,
                "Property \\'jdkTlsDisabledNamedCurves\\' does not exist in parent profile or java.security file. Cannot append", 1},
            // 14 - Test property - property value is not in existing values.
            {"Test-Profile-SetProperty.Extension_3",
                System.getProperty("test.src") + "/property-java.security", null,
                "Value \\'TestDisabledlgorithms\\' is not in existing values", 1},
            // 15 - Test property - policy sunset.
            {"Test-Profile-PolicySunset.Base",
                System.getProperty("test.src") + "/property-java.security", null,
                "Use -Dsemeru.restrictedsecurity.ignoresunsetexpiration to allow Java to start while possibly using uncertified cryptograph", 1},
            // 16 - Test property - policy sunset format.
            {"Test-Profile-PolicySunsetFormat.Base",
                System.getProperty("test.src") + "/property-java.security", null,
                "Restricted security policy sunset date is incorrect, the correct format is yyyy-MM-dd", 1},
            // 17 - Test property - secure random check 1.
            {"Test-Profile-SecureRandomCheck_1",
                System.getProperty("test.src") + "/property-java.security", null,
                "Restricted security mode secure random is missing", 1},
            // 18 - Test property - secure random check 2.
            {"Test-Profile-SecureRandomCheck_2",
                System.getProperty("test.src") + "/property-java.security", null,
                "Restricted security mode secure random is missing", 1},
            // 19 - Test constraint - constraint check 1.
            {"Test-Profile-Constraint_1",
                System.getProperty("test.src") + "/property-java.security", null,
                "Provider format is incorrect", 1},
            // 20 - Test constraint - constraint check 2.
            {"Test-Profile-Constraint_2",
                System.getProperty("test.src") + "/property-java.security", null,
                "Incorrect constraint definition for provider", 1},
            // 21 - Test constraint - constraint check 3.
            {"Test-Profile-Constraint_3",
                System.getProperty("test.src") + "/property-java.security", null,
                "Incorrect constraint definition for provider", 1},
            // 22 - Test constraint - constraint attributes check.
            {"Test-Profile-Constraint_Attributes",
                System.getProperty("test.src") + "/property-java.security", null,
                "Constraint attributes format is incorrect", 1},
            // 23 - Test constraint - constraint changed 1.
            {"Test-Profile-ConstraintChanged_1.Extension",
                System.getProperty("test.src") + "/property-java.security", null,
                "Cannot append or remove constraints since the provider (.*?) "
                    + "wasn't in this position in the profile extended", 1},
            // 24 - Test constraint - constraint changed 2.
            {"Test-Profile-ConstraintChanged_2.Extension",
                System.getProperty("test.src") + "/property-java.security", null,
                "Constraint (.*?)is not part of existing constraints", 1},
            // 25 - Test constraint - constraint changed 3.
            {"Test-Profile-ConstraintChanged_3.Base",
                System.getProperty("test.src") + "/property-java.security", null,
                "Constraints of provider not previously specified cannot be modified", 1},

            // 1 - The profile in propertyListB-java.security extends the profile
            // in propertyListA-java.security, which in turn extends the main
            // java.security profile, but propertyListB-java.security file is missing.
            {"Test-Profile-Property-List.B",
                null, System.getProperty("test.src") + "/propertyListB-java.security",
                "is not present in the java.security file or any appended files", 1}
            // 2 - The -Djava.security.propertiesList option does not support using
            // a leading '=' prefix.
            // {"Test-Profile-Property-List.A",
            //     null, "=" + System.getProperty("test.src") + "/propertyListA-java.security",
            //     "java.security.propertiesList does not support '=' prefix", 1}
        });
    }

    @Test
    public void shouldContainExpectedExitValue() throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-cp");
        args.add(System.getProperty("test.classes"));
        args.add("-Dsemeru.fips=true");
        args.add("-Dsemeru.customprofile=" + customprofile);
        if (securityPropertyFile != null) {
            args.add("-Djava.security.properties=" + securityPropertyFile);
        }
        if (securityPropertyFileList != null) {
            args.add("-Djava.security.propertiesList=" + securityPropertyFileList);
        }
        args.add("TestProperties");

        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJvm(args.toArray(new String[0]));
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(expectedExitValue).shouldMatch(expected);
    }

    public static void main(String[] args) {
        // Something to trigger "properties" debug output.
        try {
            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider Name: " + provider.getName());
                System.out.println("Provider Version: " + provider.getVersion());
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
