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


import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class verifies trust in a signature..
 */
public class FedizSignatureTrustValidator implements Validator {

    private static final Logger LOG = LoggerFactory.getLogger(FedizSignatureTrustValidator.class);

    public enum TrustType { CHAIN_TRUST, CHAIN_TRUST_CONSTRAINTS, PEER_TRUST }

    /**
     * Defines the kind of trust which is required
     */
    private TrustType signatureTrustType = TrustType.CHAIN_TRUST;

    /**
     * a collection of compiled regular expression patterns for the subject DN
     */
    private Collection<Pattern> subjectDNPatterns = new ArrayList<>();


    /**
     * Set the kind of trust. The default is CHAIN_TRUST.
     */
    public void setSignatureTrustType(TrustType trustType) {
        this.signatureTrustType = trustType;
    }

    /**
     * Set a list of Strings corresponding to regular expression constraints on
     * the subject DN of a certificate
     */
    public void setSubjectConstraints(Collection<Pattern> constraints) {
        if (constraints != null) {
            subjectDNPatterns.clear();
            subjectDNPatterns.addAll(constraints);
        }
    }

    /**
     * Validate the credential argument. It must contain either some Certificates or a PublicKey.
     *
     * A Crypto and a CallbackHandler implementation is required to be set.
     *
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null
            || ((credential.getCertificates() == null || credential.getCertificates().length == 0)
                && credential.getPublicKey() == null)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCredential");
        }

        verifyTrust(credential, data);

        return credential;
    }

    /**
     * Verify trust in the credential.
     * @param credential the Credential to be validated
     * @param data The RequestData context
     * @return A Credential instance
     * @throws WSSecurityException
     */
    protected Credential verifyTrust(
        Credential credential,
        RequestData data
    ) throws WSSecurityException {
        X509Certificate[] certs = credential.getCertificates();
        PublicKey publicKey = credential.getPublicKey();
        Crypto crypto = getCrypto(data);
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSigCryptoFile");
        }

        if (certs != null && certs.length > 0) {
            validateCertificates(certs);
            verifyTrustInCerts(certs, crypto, data, data.isRevocationEnabled());
            if (signatureTrustType.equals(TrustType.CHAIN_TRUST_CONSTRAINTS)) {
                if (matches(certs[0])) {
                    return credential;
                } else {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
                }
            } else {
                return credential;
            }
        }
        if (publicKey != null) {
            validatePublicKey(publicKey, crypto);
            return credential;
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
    }

    protected Crypto getCrypto(RequestData data) {
        return data.getSigVerCrypto();
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
                WSSecurityException.ErrorCode.FAILED_CHECK, e, "invalidCert"
            );
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_CHECK, e, "invalidCert"
            );
        }
    }

    /**
     * Evaluate whether the given certificate chain should be trusted.
     *
     * @param certificates the certificate chain that should be validated against the keystore
     * @param crypto A Crypto instance
     * @param data A RequestData instance
     * @param enableRevocation Whether revocation is enabled or not
     * @throws WSSecurityException if the certificate chain is not trusted
     */
    protected void verifyTrustInCerts(
        X509Certificate[] certificates,
        Crypto crypto,
        RequestData data,
        boolean enableRevocation
    ) throws WSSecurityException {
        //
        // Use the validation method from the crypto to check whether the subjects'
        // certificate was really signed by the issuer stated in the certificate
        //
        crypto.verifyTrust(certificates, enableRevocation, null, null);
        String subjectString = certificates[0].getSubjectX500Principal().getName();
        LOG.debug(
            "Certificate path has been verified for certificate with subject {}", subjectString
        );
    }

    /**
     * Validate a public key
     * @throws WSSecurityException
     */
    protected void validatePublicKey(PublicKey publicKey, Crypto crypto)
        throws WSSecurityException {
        crypto.verifyTrust(publicKey);
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
