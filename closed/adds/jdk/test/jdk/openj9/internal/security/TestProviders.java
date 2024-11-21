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

/*
 * @test
 * @summary Test Restricted Security Mode Provider List
 * @library /jdk/test/lib/testlibrary
 * @run junit TestProviders
 */

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import jdk.testlibrary.OutputAnalyzer;
import jdk.testlibrary.ProcessTools;

@RunWith(Parameterized.class)
public class TestProviders {

    private String customprofile;
    private String securityPropertyFile;
    private String expected;
    private int expectedExitValue;

    public TestProviders(String customprofile, String securityPropertyFile, String expected, int expectedExitValue) {
        this.customprofile = customprofile;
        this.securityPropertyFile = securityPropertyFile;
        this.expected = expected;
        this.expectedExitValue = expectedExitValue;
    }

    @Parameters
    public static List<Object[]> data() {
        return Arrays.asList(new Object[][] {
            // Test strict profile provider list.
            {"TestBase.Version",
                System.getProperty("test.src") + "/provider-java.security",
                "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunJSSE)", 0},
            // Test default profile provider list.
            {"TestBase",
                System.getProperty("test.src") + "/provider-java.security",
                "(?s)(?=.*Sun)(?=.*SunRsaSign)(?=.*SunEC)(?=.*SunJSSE)"
                    + "(?=.*SunJCE)(?=.*SunJGSS)(?=.*SunSASL)"
                    + "(?=.*XMLDSig)(?=.*SunPCSC)", 0},
            // Test extended profile provider list.
            {"TestBase.Version-Extended",
                System.getProperty("test.src") + "/provider-java.security",
                "(?s)(?=.*Sun)(?=.*SunRsaSign)(?=.*SunEC)(?=.*SunJSSE)"
                    + "(?=.*SunJCE)(?=.*SunJGSS)(?=.*SunSASL)"
                    + "(?=.*XMLDSig)(?=.*SunPCSC)", 0},
            // Test update provider list with value.
            {"Test-Profile.Updated_1",
                System.getProperty("test.src") + "/provider-java.security",
                "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunSASL)", 0},
            // Test update provider list with null.
            {"Test-Profile.Updated_2",
                System.getProperty("test.src") + "/provider-java.security",
                "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunJSSE)", 0},

            // Test base profile - provider order numbers are not consecutive.
            {"Test-Profile.Base",
                System.getProperty("test.src") + "/provider-java.security",
                "The order numbers of providers in profile RestrictedSecurity.Test-Profile.Base "
                    + "\\(or a base profile\\) are not consecutive", 1},
            // Test extended profile, provider order numbers are not consecutive.
            {"Test-Profile.Extended_1",
                System.getProperty("test.src") + "/provider-java.security",
                "The order numbers of providers in profile RestrictedSecurity.Test-Profile.Extended_1 "
                    + "\\(or a base profile\\) are not consecutive.", 1},
            // Test extended profile from another extended profile, provider order numbers are not consecutive.
            {"Test-Profile.Extended_2",
                System.getProperty("test.src") + "/provider-java.security",
                "The order numbers of providers in profile RestrictedSecurity.Test-Profile.Extended_2 "
                    + "\\(or a base profile\\) are not consecutive.", 1},
            // Test update provider list with empty, the empty is the last one in base profile.
            {"Test-Profile.Updated_3",
                System.getProperty("test.src") + "/provider-java.security",
                "Cannot add a provider in position \\d+ after removing the ones in previous positions", 1},
            // Test update provider list with empty, the empty is NOT the last one in base profile.
            {"Test-Profile.Updated_4",
                System.getProperty("test.src") + "/provider-java.security",
                "Cannot specify an empty provider in position \\d+ when non-empty ones are specified after it", 1},
            // Test base profile - one of the provider in list empty.
            {"Test-Profile.BaseOneProviderEmpty",
                System.getProperty("test.src") + "/provider-java.security",
                "Cannot specify an empty provider in position \\d+. Nothing specified before", 1},
            // Test extended profile - one of the provider in list empty.
            {"Test-Profile.ExtendedOneProviderEmpty",
                System.getProperty("test.src") + "/provider-java.security",
                "Cannot specify an empty provider in position \\d+. Nothing specified before", 1},
            // Test base profile - no provider list.
            {"Test-Profile.BaseNoProviderList",
                System.getProperty("test.src") + "/provider-java.security",
                "No providers are specified as part of the Restricted Security profile", 1},
            // Test profile - provider must be specified using the fully-qualified class name.
            {"Test-Profile.ProviderClassName",
                System.getProperty("test.src") + "/provider-java.security",
                "Provider must be specified using the fully-qualified class name", 1},
            // Test profile - provider format is incorrect.
            {"Test-Profile.ProviderFormat",
                System.getProperty("test.src") + "/provider-java.security",
                "Provider format is incorrect", 1}
        });
    }

    @Test
    public void shouldContainExpectedExitValue() throws Throwable {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJvm(
                "-cp", System.getProperty("test.classes"),
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                "TestProviders");
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
