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
 * @summary Test Restricted Security Mode Constraints
 * @library /test/lib
 * @run junit TestConstraintsSuccess
 */
import org.junit.jupiter.api.Test;

import java.security.AlgorithmParameterGenerator;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestConstraintsSuccess {

    private static void getInstances() throws Exception {
        CertificateFactory.getInstance("X.509");
        CertPathValidator.getInstance("PKIX");
        MessageDigest.getInstance("SHA-512");
        KeyStore.getInstance("JKS");
        Signature.getInstance("SHA256withECDSA");
        KeyPairGenerator.getInstance("EC");
        KeyAgreement.getInstance("ECDH");
        KeyFactory.getInstance("EC");
        Cipher.getInstance("RSA");
        KeyGenerator.getInstance("AES");
        AlgorithmParameterGenerator.getInstance("DiffieHellman");
        SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        Mac.getInstance("HmacSHA256");
        KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory.getInstance("SunX509");
        SSLContext.getInstance("TLSv1.3");

        // Since there are three constraints for MD5, with only the middle one
        // allowing for use by this class, successfully getting the algorithm
        // verifies that all constraints are checked.
        MessageDigest.getInstance("MD5");

        // Since there are three constraints for SHA1withECDSA, with only the
        // middle one having the correct attributes, successfully getting the
        // algorithm verifies that all constraints are checked.
        Signature.getInstance("SHA1withECDSA");
    }

    @Test
    public void runWithConstraints() throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.customprofile=TestConstraints.Version",
                "-Djava.security.properties=" + System.getProperty("test.src") + "/constraints-java.security",
                "TestConstraintsSuccess"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(0);
    }

    public static void main(String[] args) throws Exception {
        getInstances();
    }
}
