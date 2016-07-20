/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.fediz.core.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Properties;

import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CertsUtils {
    
    private static final Logger LOG = LoggerFactory.getLogger(CertsUtils.class);
    
    private CertsUtils() {
        super();
    }
    
    /**
     * Load an X.509 Certificate from a certificate file
     */
    public static X509Certificate getX509CertificateFromFile(String filename) throws CertificateException {
        return getX509CertificateFromFile(filename,
                                  Thread.currentThread().getContextClassLoader());
    }
    
    /**
     * Load an X.509 Certificate from a certificate file
     */
    public static X509Certificate getX509CertificateFromFile(String filename, ClassLoader classLoader) 
        throws CertificateException {
        if (filename == null) {
            return null;
        }
        
        ClassLoader cl = classLoader;
        if (cl == null) {
            cl = Thread.currentThread().getContextClassLoader();
        }

        try (InputStream is = Merlin.loadInputStream(cl, filename);
            BufferedInputStream bis = new BufferedInputStream(is)) {

            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            if (bis.available() > 0) {
                Certificate cert = cf.generateCertificate(bis);
                if (!(cert instanceof X509Certificate)) {
                    LOG.error("Certificate " + filename + " is not of type X509Certificate");
                    throw new RuntimeException("Certificate "
                                                            + filename + " is not of type X509Certificate");
                }
                if (bis.available() > 0) {
                    LOG.warn("There are more certificates configured in " + filename + ". Only first is parsed");
                }
                return (X509Certificate)cert;    
            } else  {
                LOG.error("No bytes can be read in certificate file " + filename);
                throw new RuntimeException("No bytes can be read in certificate file " + filename);
            }
        } catch (WSSecurityException ex) {
            LOG.error("Failed to read certificate file " + filename, ex);
            throw new RuntimeException("Failed to read certificate file " + filename, ex);
        } catch (IOException ex) {
            LOG.error("Failed to read keystore", ex);
            throw new RuntimeException("Failed to read keystore");
        }
    }
    
    /**
     * Load an X.509 Certificate from a WSS4J Crypto instance using a keystore alias
     */
    public static X509Certificate getX509CertificateFromCrypto(Crypto crypto, String keyAlias) 
        throws WSSecurityException {
        if (keyAlias == null || "".equals(keyAlias)) {
            keyAlias = crypto.getDefaultX509Identifier();
        }
        
        if (keyAlias == null) {
            throw new RuntimeException("No keystore alias was specified to sign the metadata");
        }
        
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(keyAlias);
        X509Certificate[] issuerCerts = crypto.getX509Certificates(cryptoType);
        if (issuerCerts == null || issuerCerts.length == 0) {
            throw new RuntimeException(
                    "No issuer certs were found to sign the metadata using issuer name: "
                            + keyAlias);
        }
        return issuerCerts[0];
    }
    
    /**
     * Parse a String parameter into an X.509 Certificate. The parameter can be either the encoded cert, or else
     * a filename containing the certificate.
     */
    public static X509Certificate parseX509Certificate(String certificate) 
        throws CertificateException, WSSecurityException, ProcessingException, Base64DecodingException, IOException {
        if (certificate == null) {
            return null;
        }
        
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            try {
                return CertsUtils.getX509CertificateFromFile(certificate);
            } catch (CertificateException ex) {
                // Maybe it's a WSS4J properties file...
                Crypto crypto = CertsUtils.getCryptoFromFile(certificate);
                if (crypto != null) {
                    return CertsUtils.getX509CertificateFromCrypto(crypto, null);
                }
            }
        } 
        
        // Here the certificate is encoded in the configuration file
        try {
            return CertsUtils.parseCertificate(certificate);
        } catch (Exception ex) {
            LOG.error("Failed to parse trusted certificate", ex);
            throw new ProcessingException("Failed to parse trusted certificate");
        }
    }
   
    /**
     * Get a Crypto instance from a file
     */
    public static Crypto getCryptoFromFile(String filename) {
        Crypto crypto = null;
        Properties prop = new Properties();
        try {
            //load a properties file
            InputStream is = Merlin.loadInputStream(Thread.currentThread().getContextClassLoader(), filename);
            prop.load(is);
            crypto = CryptoFactory.getInstance(prop);
        } catch (WSSecurityException ex) {
            LOG.error("Failed to load keystore " + prop.toString(), ex);
            throw new RuntimeException("Failed to load keystore " + prop.toString());
        } catch (IOException ex) {
            LOG.error("Failed to read signing metadata key", ex);
            throw new RuntimeException("Failed to read signing metadata key");
        }
        return crypto;
    }
    
    /**
     * Get a crypto instance using a certificate
     */
    public static Crypto getCryptoFromCertificate(String certificate) throws ProcessingException {
        if (certificate == null) {
            return null;
        }
        
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            try {
                X509Certificate cert = CertsUtils.getX509CertificateFromFile(certificate);
                if (cert == null) {
                    return null;
                }
                return new CertificateStore(new X509Certificate[]{cert});
            } catch (CertificateException ex) {
                // Maybe it's a WSS4J properties file...
                return CertsUtils.getCryptoFromFile(certificate);
            }
        } 
        
        // Here the certificate is encoded in the configuration file
        X509Certificate cert;
        try {
            cert = CertsUtils.parseCertificate(certificate);
        } catch (Exception ex) {
            LOG.error("Failed to parse trusted certificate", ex);
            throw new ProcessingException("Failed to parse trusted certificate");
        }
        return new CertificateStore(Collections.singletonList(cert).toArray(new X509Certificate[0]));
    }
    
    private static X509Certificate parseCertificate(String certificate)
        throws CertificateException, Base64DecodingException, IOException {
        
        //before decoding we need to get rid off the prefix and suffix
        byte[] decoded = Base64.decode(certificate.replaceAll("-----BEGIN CERTIFICATE-----", "").
                                        replaceAll("-----END CERTIFICATE-----", ""));

        try (InputStream is = new ByteArrayInputStream(decoded)) {
            return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }
    
}
