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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.cxf.fediz.core.saml.FedizSignatureTrustValidator.TRUST_TYPE;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class validates a SAML Assertion, which is wrapped in an "AssertionWrapper" instance.
 * It assumes that the AssertionWrapper instance has already verified the signature on the
 * assertion (done by the SAMLTokenProcessor). It verifies trust in the signature, and also
 * checks that the Subject contains a KeyInfo (and processes it) for the holder-of-key case,
 * and verifies that the Assertion is signed as well for holder-of-key. 
 */
public class SamlAssertionValidator implements Validator {
    
    private static final Logger LOG = LoggerFactory.getLogger(SamlAssertionValidator.class);
    
    /**
     * The time in seconds in the future within which the NotBefore time of an incoming 
     * Assertion is valid. The default is 60 seconds.
     */
    private int futureTTL = 60;
    
    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    private boolean validateSignatureAgainstProfile = true;

    private TRUST_TYPE signatureTrustType = TRUST_TYPE.CHAIN_TRUST;
        
    /**
     * a collection of compiled regular expression patterns for the subject DN
     */
    private Collection<Pattern> subjectDNPatterns = new ArrayList<Pattern>();
    
    
    /**
     * Set the time in seconds in the future within which the NotBefore time of an incoming 
     * Assertion is valid. The default is 60 seconds.
     */
    public void setFutureTTL(int newFutureTTL) {
        futureTTL = newFutureTTL;
    }
    
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
     * Validate the credential argument. It must contain a non-null AssertionWrapper. 
     * A Crypto and a CallbackHandler implementation is also required to be set.
     * 
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getSamlAssertion() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCredential");
        }
        SamlAssertionWrapper assertion = credential.getSamlAssertion();
        
        // Check HOK requirements
        String confirmMethod = null;
        List<String> methods = assertion.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod)) {
            if (assertion.getSubjectKeyInfo() == null) {
                LOG.debug("There is no Subject KeyInfo to match the holder-of-key subject conf method");
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKeyInSAMLToken");
            }
            // The assertion must have been signed for HOK
            if (!assertion.isSigned()) {
                LOG.debug("A holder-of-key assertion must be signed");
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }
        }
        
        // Check conditions
        checkConditions(assertion);
        
        // Check OneTimeUse Condition
        checkOneTimeUse(assertion, data);
        
        // Validate the assertion against schemas/profiles
        validateAssertion(assertion);

        // Verify trust on the signature
        if (assertion.isSigned()) {
            verifySignedAssertion(assertion, data);
        }
        return credential;
    }
    
    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     * @param assertion The signed Assertion
     * @param data The RequestData context
     * @return A Credential instance
     * @throws WSSecurityException
     */
    protected Credential verifySignedAssertion(
        SamlAssertionWrapper assertion,
        RequestData data
    ) throws WSSecurityException {
        Credential credential = new Credential();
        SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
        credential.setPublicKey(samlKeyInfo.getPublicKey());
        credential.setCertificates(samlKeyInfo.getCerts());
        
        FedizSignatureTrustValidator trustValidator = new FedizSignatureTrustValidator();
        trustValidator.setSignatureTrustType(signatureTrustType);
        trustValidator.setSubjectConstraints(subjectDNPatterns);
        
        return trustValidator.validate(credential, data);
    }

    protected Crypto getCrypto(RequestData data) {
        return data.getSigVerCrypto();
    }

    /**
     * Check the Conditions of the Assertion.
     */
    protected void checkConditions(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        samlAssertion.checkConditions(futureTTL);
    }
    
    /**
     * Check the "OneTimeUse" Condition of the Assertion. If this is set then the Assertion
     * is cached (if a cache is defined), and must not have been previously cached
     */
    protected void checkOneTimeUse(
        SamlAssertionWrapper samlAssertion, RequestData data
    ) throws WSSecurityException {
        if (samlAssertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && samlAssertion.getSaml2().getConditions() != null
            && samlAssertion.getSaml2().getConditions().getOneTimeUse() != null
            && data.getSamlOneTimeUseReplayCache() != null) {
            String identifier = samlAssertion.getId();
            
            ReplayCache replayCache = data.getSamlOneTimeUseReplayCache();
            if (replayCache.contains(identifier)) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "badSamlToken",
                    "A replay attack has been detected");
            }
            
            DateTime expires = samlAssertion.getSaml2().getConditions().getNotOnOrAfter();
            if (expires != null) {
                Date rightNow = new Date();
                long currentTime = rightNow.getTime();
                long expiresTime = expires.getMillis();
                replayCache.add(identifier, 1L + (expiresTime - currentTime) / 1000L);
            } else {
                replayCache.add(identifier);
            }
            
            replayCache.add(identifier);
        }
    }
    
    /**
     * Validate the samlAssertion against schemas/profiles
     */
    protected void validateAssertion(SamlAssertionWrapper samlAssertion) throws WSSecurityException {
        samlAssertion.validateAssertion(validateSignatureAgainstProfile);
    }
    
    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    public boolean isValidateSignatureAgainstProfile() {
        return validateSignatureAgainstProfile;
    }

    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    public void setValidateSignatureAgainstProfile(boolean validateSignatureAgainstProfile) {
        this.validateSignatureAgainstProfile = validateSignatureAgainstProfile;
    }
    
}
