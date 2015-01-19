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

package org.apache.cxf.fediz.core.saml;


import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.validate.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class validates a SAML Assertion by wrapping the default WSS4J SamlAssertionValidator.
 * It extends it by verifying trust in the Signature using a TRUST_TYPE, as well as subject DN
 * constraints.
 */
public class SamlAssertionValidator extends org.apache.ws.security.validate.SamlAssertionValidator {
    
    private static final Logger LOG = LoggerFactory.getLogger(SamlAssertionValidator.class);
    
    public enum TRUST_TYPE { CHAIN_TRUST, CHAIN_TRUST_CONSTRAINTS, PEER_TRUST }
    
    /**
     * Defines the kind of trust which is required thus assertion signature validation is successful.
     */
    private TRUST_TYPE signatureTrustType = TRUST_TYPE.CHAIN_TRUST;
        
    /**
     * a collection of compiled regular expression patterns for the subject DN
     */
    private Collection<Pattern> subjectDNPatterns = new ArrayList<Pattern>();
    
    /**
     * Set the kind of trust. The default is CHAIN_TRUST.
     */
    public void setSignatureTrustType(TRUST_TYPE trustType) {
        this.signatureTrustType = trustType;
    }
    
    /**
     * Set a list of Strings corresponding to regular expression constraints on
     * the subject DN of a certificate
     */
    public void setSubjectConstraints(List<String> constraints) {
        if (constraints != null) {
            subjectDNPatterns = new ArrayList<Pattern>();
            for (String constraint : constraints) {
                try {
                    subjectDNPatterns.add(Pattern.compile(constraint.trim()));
                } catch (PatternSyntaxException ex) {
                    // LOG.severe(ex.getMessage());
                    throw ex;
                }
            }
        }
    }
    
    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     * @param assertion The signed Assertion
     * @param data The RequestData context
     * @return A Credential instance
     * @throws WSSecurityException
     */
    @Override
    protected Credential verifySignedAssertion(
        AssertionWrapper assertion,
        RequestData data
    ) throws WSSecurityException {
        Credential credential = new Credential();
        SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
        credential.setPublicKey(samlKeyInfo.getPublicKey());
        credential.setCertificates(samlKeyInfo.getCerts());
        
        X509Certificate[] certs = credential.getCertificates();
        PublicKey publicKey = credential.getPublicKey();
        Crypto crypto = getCrypto(data);
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
        }
        
        if (certs != null && certs.length > 0) {
            validateCertificates(certs);
            boolean trust = false;
            boolean enableRevocation = data.isRevocationEnabled();
            if (certs.length == 1) {
                trust = verifyTrustInCert(certs[0], crypto, enableRevocation);
            } else {
                trust = verifyTrustInCerts(certs, crypto, enableRevocation);
            }
            if (trust) {
                if (signatureTrustType.equals(TRUST_TYPE.CHAIN_TRUST_CONSTRAINTS)) {
                    if (matches(certs[0])) {
                        return credential;
                    } else {
                        throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
                    }
                } else {
                    return credential;
                }
            }
        }
        if (publicKey != null) {
            boolean trust = validatePublicKey(publicKey, crypto);
            if (trust) {
                return credential;
            }
        }
        throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
    }

    protected Crypto getCrypto(RequestData data) {
        return data.getSigCrypto();
    }


    /**
     * Validate the certificates by checking the validity of each cert
     * @throws WSSecurityException
     */
    protected void validateCertificates(X509Certificate[] certificates) 
        throws WSSecurityException {
        try {
            for (int i = 0; i < certificates.length; i++) {
                certificates[i].checkValidity();
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "invalidCert", null, e
            );
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "invalidCert", null, e
            );
        }
    }
    
    /**
     * Evaluate whether a given certificate should be trusted.
     * 
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer 
     * might be fooled by a phony DN (String!)
     *
     * @param cert the certificate that should be validated against the keystore
     * @param crypto A crypto instance to use for trust validation
     * @param enableRevocation Whether revocation is enabled or not
     * @return true if the certificate is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCert(
        X509Certificate cert, 
        Crypto crypto,
        boolean enableRevocation
    ) throws WSSecurityException {
        String subjectString = cert.getSubjectX500Principal().getName();
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Transmitted certificate has subject " + subjectString);
            LOG.debug(
                "Transmitted certificate has issuer " + issuerString + " (serial " 
                + issuerSerial + ")"
            );
        }

        //
        // FIRST step - Search the keystore for the transmitted certificate
        //              If peer trust is enforced then validation fails if
        //              certificate not found in keystore
        //
        boolean isInKeystore = isCertificateInKeyStore(crypto, cert);
        if (!enableRevocation && isInKeystore) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate " + subjectString + " found in keystore"
                );
            }
            return true;
        }
        if (!isInKeystore && signatureTrustType.equals(TRUST_TYPE.PEER_TRUST)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate " + subjectString + " not found in keystore"
                );
            }
            return false;
        }

        //
        // SECOND step - Search for the issuer cert (chain) of the transmitted certificate in the 
        // keystore or the truststore
        //
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.SUBJECT_DN);
        cryptoType.setSubjectDN(issuerString);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        // If the certs have not been found, the issuer is not in the keystore/truststore
        // As a direct result, do not trust the transmitted certificate
        if (foundCerts == null || foundCerts.length < 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "No certs found in keystore for issuer " + issuerString 
                    + " of certificate for " + subjectString
                );
            }
            return false;
        }

        //
        // THIRD step
        // Check the certificate trust path for the issuer cert chain
        //
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Preparing to validate certificate path for issuer " + issuerString
            );
        }
        //
        // Form a certificate chain from the transmitted certificate
        // and the certificate(s) of the issuer from the keystore/truststore
        //
        X509Certificate[] x509certs = new X509Certificate[foundCerts.length + 1];
        x509certs[0] = cert;
        for (int j = 0; j < foundCerts.length; j++) {
            x509certs[j + 1] = (X509Certificate)foundCerts[j];
        }

        //
        // Use the validation method from the crypto to check whether the subjects' 
        // certificate was really signed by the issuer stated in the certificate
        //
        if (crypto.verifyTrust(x509certs, enableRevocation)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate path has been verified for certificate with subject " 
                     + subjectString
                );
            }
            return true;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Certificate path could not be verified for certificate with subject " 
                + subjectString
            );
        }
        return false;
    }
    
    /**
     * Check to see if the certificate argument is in the keystore
     * @param crypto A Crypto instance to use for trust validation
     * @param cert The certificate to check
     * @return true if cert is in the keystore
     * @throws WSSecurityException
     */
    protected boolean isCertificateInKeyStore(
        Crypto crypto,
        X509Certificate cert
    ) throws WSSecurityException {
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();
        
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
        cryptoType.setIssuerSerial(issuerString, issuerSerial);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        //
        // If a certificate has been found, the certificates must be compared
        // to ensure against phony DNs (compare encoded form including signature)
        //
        if (foundCerts != null && foundCerts[0] != null && foundCerts[0].equals(cert)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Direct trust for certificate with " + cert.getSubjectX500Principal().getName()
                );
            }
            return true;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "No certificate found for subject from issuer with " + issuerString 
                + " (serial " + issuerSerial + ")"
            );
        }
        return false;
    }
    
    /**
     * Evaluate whether the given certificate chain should be trusted.
     * 
     * @param certificates the certificate chain that should be validated against the keystore
     * @param crypto A Crypto instance
     * @param enableRevocation Whether revocation is enabled or not
     * @return true if the certificate chain is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCerts(
        X509Certificate[] certificates, 
        Crypto crypto,
        boolean enableRevocation
    ) throws WSSecurityException {
        if (certificates == null || certificates.length < 2) {
            return false;
        }
        
        String subjectString = certificates[0].getSubjectX500Principal().getName();
        //
        // Use the validation method from the crypto to check whether the subjects' 
        // certificate was really signed by the issuer stated in the certificate
        //
        if (crypto.verifyTrust(certificates, enableRevocation)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate path has been verified for certificate with subject " 
                    + subjectString
                );
            }
            return true;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Certificate path could not be verified for certificate with subject " 
                + subjectString
            );
        }
            
        return false;
    }
    
    /**
     * Validate a public key
     * @throws WSSecurityException
     */
    protected boolean validatePublicKey(PublicKey publicKey, Crypto crypto) 
        throws WSSecurityException {
        return crypto.verifyTrust(publicKey);
    }
    
    /**
     * @return true if the certificate's SubjectDN matches the constraints
     *         defined in the subject DNConstraints; false, otherwise. The
     *         certificate subject DN only has to match ONE of the subject cert
     *         constraints (not all).
     */
    public boolean matches(final java.security.cert.X509Certificate cert) {
        if (!subjectDNPatterns.isEmpty()) {
            if (cert == null) {
                return false;
            }
            String subjectName = cert.getSubjectX500Principal().getName();
            boolean subjectMatch = false;
            for (Pattern subjectDNPattern : subjectDNPatterns) {
                final Matcher matcher = subjectDNPattern.matcher(subjectName);
                if (matcher.matches()) {
                    subjectMatch = true;
                    break;
                }
            }
            if (!subjectMatch) {
                return false;
            }
        }

        return true;
    }
    
}
