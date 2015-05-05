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
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CertsUtils {
    
    private static final Logger LOG = LoggerFactory.getLogger(CertsUtils.class);
    
    private CertsUtils() {
        super();
    }
    
    public static X509Certificate getX509Certificate(String filename) {
        return getX509Certificate(filename, Thread.currentThread().getContextClassLoader());
    }
    
    public static X509Certificate getX509Certificate(String filename, ClassLoader classLoader) {
        ClassLoader cl = classLoader;
        if (cl == null) {
            cl = Thread.currentThread().getContextClassLoader();
        }
        BufferedInputStream bis = null;
        try {
            
            InputStream is = Merlin.loadInputStream(cl, filename);
            
            bis = new BufferedInputStream(is);

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
        } catch (Exception ex) {
            LOG.error("Failed to read certificate file " + filename, ex);
            throw new RuntimeException("Failed to read certificate file " + filename, ex);
        } finally {
            try {
                bis.close();
            } catch (IOException ex) {
                LOG.error("Failed to close certificate file " + filename, ex);
            }
        }
    }
    
    public static Crypto createCrypto(String filename) {
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
    
    public static X509Certificate getX509Certificate(Crypto crypto, String keyAlias) throws WSSecurityException {
        if (keyAlias == null || "".equals(keyAlias)) {
            keyAlias = crypto.getDefaultX509Identifier();
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
}
