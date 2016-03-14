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

package org.apache.cxf.fediz.service.idp.protocols;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.spi.TrustedIdpProtocolHandler;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractTrustedIdpProtocolHandler implements TrustedIdpProtocolHandler {
    
    private static final Logger LOG = LoggerFactory.getLogger(AbstractTrustedIdpProtocolHandler.class);
    
    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        // TODO Auto-generated method stub
        return false;
    }

    protected Crypto getCrypto(String certificate) throws ProcessingException {
        if (certificate == null) {
            return null;
        }
        
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            try {
                X509Certificate cert = CertsUtils.getX509Certificate(certificate);
                if (cert == null) {
                    return null;
                }
                return new CertificateStore(new X509Certificate[]{cert});
            } catch (CertificateException ex) {
                // Maybe it's a WSS4J properties file...
                return CertsUtils.createCrypto(certificate);
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
    
    protected X509Certificate getCertificate(String certificate) 
        throws CertificateException, WSSecurityException, ProcessingException, Base64DecodingException, IOException {
        if (certificate == null) {
            return null;
        }
        
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            try {
                return CertsUtils.getX509Certificate(certificate);
            } catch (CertificateException ex) {
                // Maybe it's a WSS4J properties file...
                Crypto crypto = CertsUtils.createCrypto(certificate);
                if (crypto != null) {
                    return CertsUtils.getX509Certificate(crypto, null);
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
    
    protected String getProperty(TrustedIdp trustedIdp, String property) {
        Map<String, String> parameters = trustedIdp.getParameters();
        
        if (parameters != null && parameters.containsKey(property)) {
            return parameters.get(property);
        }
        
        return null;
    }
    
    // Is a property configured. Defaults to the boolean "defaultValue" if not
    protected boolean isBooleanPropertyConfigured(TrustedIdp trustedIdp, String property, boolean defaultValue) {
        Map<String, String> parameters = trustedIdp.getParameters();
        
        if (parameters != null && parameters.containsKey(property)) {
            return Boolean.parseBoolean(parameters.get(property));
        }
        
        return defaultValue;
    }
    
}
