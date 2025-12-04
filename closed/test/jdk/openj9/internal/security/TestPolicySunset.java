/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2025, 2025 All Rights Reserved
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
 * @summary Test Restricted Security Mode Policy Sunset
 * @library /jdk/test/lib/testlibrary
 * @run junit TestPolicySunset
 */

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import jdk.testlibrary.OutputAnalyzer;
import jdk.testlibrary.ProcessTools;

@RunWith(Parameterized.class)
public class TestPolicySunset {

    private String customprofile;
    private String securityPropertyFile;
    private String suppresssunsetwarning;
    private String ignoresunsetexpiration;
    private String expected;
    private int exitValue;

    public TestPolicySunset(String customprofile, String securityPropertyFile,
            String suppresssunsetwarning, String ignoresunsetexpiration, String expected, int exitValue) {
        this.customprofile = customprofile;
        this.securityPropertyFile = securityPropertyFile;
        this.suppresssunsetwarning = suppresssunsetwarning;
        this.ignoresunsetexpiration = ignoresunsetexpiration;
        this.expected = expected;
        this.exitValue = exitValue;
    }

    private static Path updateExpireSoonSunsetFile(String baseFile) {
        BufferedReader reader = null;
        BufferedWriter writer = null;
        try {
            LocalDate soonDate = LocalDate.now(Clock.systemUTC()).plusMonths(1);
            String newDate = soonDate.format(DateTimeFormatter.ISO_DATE);

            reader = Files.newBufferedReader(Paths.get(baseFile), StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append(System.lineSeparator());
            }
            String content = sb.toString();

            String pattern = "(?m)^(RestrictedSecurity\\.Test-Profile-PolicySunset-ExpireSoon\\.desc\\.sunsetDate)\\s*=.*$";
            String updated = content.replaceAll(pattern, "$1 = " + newDate);

            Path tmp = Files.createTempFile("sunset-java.security.expireSoon.", ".tmp");
            writer = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8);
            writer.write(updated);
            writer.flush();

            return tmp;
        } catch (IOException e) {
            throw new RuntimeException("Failed to update sunset date for ExpireSoon profile", e);
        }
    }

    @Parameters
    public static List<Object[]> data() {
        String propertyFile = System.getProperty("test.src") + "/sunset-java.security";
        String updatedPropertyFile = updateExpireSoonSunsetFile(propertyFile).toString();

        return Arrays.asList(new Object[][] {
                // 1 - expired; suppress=false; ignore=true
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=false", "=true",
                        "WARNING: Java will start with the requested restricted security profile but uncertified cryptography may be active",
                        0},
                // 2 - expired; suppress=true; ignore=true, no warning
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=true", "=true",
                        "",
                        0},
                // 3 - expire soon (<=6 months); suppress=false
                {"Test-Profile-PolicySunset-ExpireSoon",
                        updatedPropertyFile,
                        "=false", "=false",
                        "The restricted security profile RestrictedSecurity.Test-Profile-PolicySunset-ExpireSoon will expire",
                        0},
                // 4 - expire soon (<=6 months); suppress=true, no warning
                {"Test-Profile-PolicySunset-ExpireSoon",
                        updatedPropertyFile,
                        "=true", "=false",
                        "",
                        0},
                // 5 - not expire (>6 months); no warning
                {"Test-Profile-PolicySunset-NotExpire",
                        propertyFile,
                        "=false", "=false",
                        "",
                        0},
                // 6 - expired; property treat empty as true, no warning
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "", "",
                        "",
                        0},
                // 7 - expired; suppress unset, ignore=true
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        null, "=true",
                        "WARNING: Java will start with the requested restricted security profile but uncertified cryptography may be active",
                        0},
                // 8 - expired; suppress=false; ignore=false
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=false", "=false",
                        "Use -Dsemeru.restrictedsecurity.ignoresunsetexpiration to allow Java to start while possibly using uncertified cryptography",
                        1},
                // 9 - expired; suppress=true; ignore=false, no warning
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=true", "=false",
                        "",
                        1},
                // 10 - expired; suppress=true, ignore unset, no warning
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=true", null,
                        "",
                        1},
                // 11 - expired; suppress=false; ignore unset
                {"Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=false", null,
                        "Use -Dsemeru.restrictedsecurity.ignoresunsetexpiration to allow Java to start while possibly using uncertified cryptography",
                        1}
        });
    }

    @Test
    public void shouldContain_testPolicySunset() throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-cp");
        args.add(System.getProperty("test.classes"));
        args.add("-Dsemeru.fips=true");
        args.add("-Dsemeru.customprofile=" + customprofile);
        args.add("-Djava.security.properties=" + securityPropertyFile);
        if (suppresssunsetwarning != null) {
            args.add("-Dsemeru.restrictedsecurity.suppresssunsetwarning" + suppresssunsetwarning);
        }
        if (ignoresunsetexpiration != null) {
            args.add("-Dsemeru.restrictedsecurity.ignoresunsetexpiration" + ignoresunsetexpiration);
        }
        args.add("TestPolicySunset");

        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJvm(args.toArray(new String[0]));
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(exitValue).shouldMatch(expected);
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
