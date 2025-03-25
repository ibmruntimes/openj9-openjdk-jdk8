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
 * @library /jdk/test/lib/testlibrary
 * @run junit TestConstraintsFailure
 */
import org.junit.Test;

import java.security.AlgorithmParameterGenerator;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateException;
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

import jdk.testlibrary.OutputAnalyzer;
import jdk.testlibrary.ProcessTools;

public class TestConstraintsFailure {

    private static void getInstances() throws Exception {
        try {
            CertificateFactory.getInstance("X.509");
            throw new RuntimeException("A CertificateException should have been thrown");
        } catch (CertificateException ce) {
            // Do nothing. This is expected.
        }
        try {
            CertPathValidator.getInstance("PKIX");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            MessageDigest.getInstance("SHA-512");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            KeyStore.getInstance("JKS");
            throw new RuntimeException("A KeyStoreException should have been thrown");
        } catch (KeyStoreException ke) {
            // Do nothing. This is expected.
        }
        try {
            Signature.getInstance("SHA256withECDSA");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            KeyPairGenerator.getInstance("EC");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            KeyAgreement.getInstance("ECDH");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            KeyFactory.getInstance("EC");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            Cipher.getInstance("RSA");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            KeyGenerator.getInstance("AES");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            AlgorithmParameterGenerator.getInstance("DiffieHellman");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            Mac.getInstance("HmacSHA256");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }

        try {
            KeyManagerFactory.getInstance("SunX509");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            TrustManagerFactory.getInstance("SunX509");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
        try {
            SSLContext.getInstance("TLSv1.3");
            throw new RuntimeException("A NoSuchAlgorithmException should have been thrown");
        } catch (NoSuchAlgorithmException nsae) {
            // Do nothing. This is expected.
        }
    }

    @Test
    public void runWithConstraints() throws Throwable {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJvm(
                "-cp", System.getProperty("test.classes"),
                "-Dsemeru.customprofile=TestConstraints.Version",
                "-Djava.security.properties=" + System.getProperty("test.src") + "/constraints-java.security",
                "TestConstraintsFailure"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(0);
    }

    public static void main(String[] args) throws Exception {
        getInstances();
    }
}
