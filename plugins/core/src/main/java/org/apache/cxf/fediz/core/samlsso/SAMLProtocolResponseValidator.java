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
package org.apache.cxf.fediz.core.samlsso;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.w3c.dom.Document;
import org.apache.cxf.fediz.core.config.CertificateValidationMethod;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.TrustManager;
import org.apache.cxf.fediz.core.config.TrustedIssuer;
import org.apache.cxf.fediz.core.saml.FedizSignatureTrustValidator;
import org.apache.cxf.fediz.core.saml.FedizSignatureTrustValidator.TRUST_TYPE;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.validate.Credential;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validate a SAML (1.1 or 2.0) Protocol Response. It validates the Response against the specs,
 * the signature of the Response (if it exists), and any internal Assertion stored in the Response 
 * - including any signature. It validates the status code of the Response as well.
 */
public class SAMLProtocolResponseValidator {
    
    public static final String SAML2_STATUSCODE_SUCCESS = 
        "urn:oasis:names:tc:SAML:2.0:status:Success";
    public static final String SAML1_STATUSCODE_SUCCESS = "Success";
    
    private static final Logger LOG = LoggerFactory.getLogger(SAMLProtocolResponseValidator.class);
    
    // private Validator signatureValidator = new SignatureTrustValidator();
    
    /**
     * Validate a SAML 2 Protocol Response
     * @param samlResponse
     * @throws WSSecurityException
     */
    public void validateSamlResponse(
        org.opensaml.saml2.core.Response samlResponse,
        FedizContext config
    ) throws WSSecurityException {
        // Check the Status Code
        if (samlResponse.getStatus() == null
            || samlResponse.getStatus().getStatusCode() == null) {
            LOG.debug("Either the SAML Response Status or StatusCode is null");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        if (!SAML2_STATUSCODE_SUCCESS.equals(samlResponse.getStatus().getStatusCode().getValue())) {
            LOG.debug(
                "SAML Status code of " + samlResponse.getStatus().getStatusCode().getValue()
                + "does not equal " + SAML2_STATUSCODE_SUCCESS
            );
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        
        validateResponseAgainstSchemas(samlResponse);
        validateResponseSignature(samlResponse, config);
    }
    
    /**
     * Validate a SAML 1.1 Protocol Response
     * @param samlResponse
     * @throws WSSecurityException
     */
    public void validateSamlResponse(
        org.opensaml.saml1.core.Response samlResponse,
        FedizContext config
    ) throws WSSecurityException {
        // Check the Status Code
        if (samlResponse.getStatus() == null
            || samlResponse.getStatus().getStatusCode() == null
            || samlResponse.getStatus().getStatusCode().getValue() == null) {
            LOG.debug("Either the SAML Response Status or StatusCode is null");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        String statusValue = samlResponse.getStatus().getStatusCode().getValue().getLocalPart();
        if (!SAML1_STATUSCODE_SUCCESS.equals(statusValue)) {
            LOG.debug(
                "SAML Status code of " + samlResponse.getStatus().getStatusCode().getValue()
                + "does not equal " + SAML1_STATUSCODE_SUCCESS
            );
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        validateResponseAgainstSchemas(samlResponse);
        validateResponseSignature(samlResponse, config);
    }
    
    /**
     * Validate the Response against the schemas
     */
    private void validateResponseAgainstSchemas(
        org.opensaml.saml2.core.Response samlResponse
    ) throws WSSecurityException {
        // Validate SAML Response against schemas
        ValidatorSuite schemaValidators = 
            org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
        try {
            schemaValidators.validate(samlResponse);
        } catch (ValidationException e) {
            LOG.debug("Saml Validation error: " + e.getMessage(), e);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
    }
    
    /**
     * Validate the Response against the schemas
     */
    private void validateResponseAgainstSchemas(
        org.opensaml.saml1.core.Response samlResponse
    ) throws WSSecurityException {
        // Validate SAML Response against schemas
        ValidatorSuite schemaValidators = 
            org.opensaml.Configuration.getValidatorSuite("saml1-core-schema-validator");
        try {
            schemaValidators.validate(samlResponse);
        } catch (ValidationException e) {
            LOG.debug("Saml Validation error: " + e.getMessage(), e);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
    }
    
    /**
     * Validate the Response signature (if it exists)
     */
    private void validateResponseSignature(
        org.opensaml.saml2.core.Response samlResponse,
        FedizContext config
    ) throws WSSecurityException {
        if (!samlResponse.isSigned()) {
            return;
        }
        
        validateResponseSignature(
            samlResponse.getSignature(), samlResponse.getDOM().getOwnerDocument(), config
        );
    }
    
    /**
     * Validate the Response signature (if it exists)
     */
    private void validateResponseSignature(
        org.opensaml.saml1.core.Response samlResponse,
        FedizContext config
    ) throws WSSecurityException {
        if (!samlResponse.isSigned()) {
            return;
        }
        
        validateResponseSignature(
            samlResponse.getSignature(), samlResponse.getDOM().getOwnerDocument(), config
        );
    }
    
    /**
     * Validate the response signature
     */
    private void validateResponseSignature(
        Signature signature, 
        Document doc,
        FedizContext config
    ) throws WSSecurityException {
        RequestData requestData = new RequestData();
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        requestData.setWssConfig(wssConfig);
        
        SAMLKeyInfo samlKeyInfo = null;
        
        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo != null) {
            try {
                samlKeyInfo = 
                    SAMLUtil.getCredentialFromKeyInfo(
                        keyInfo.getDOM(), new WSSSAMLKeyInfoProcessor(requestData, new WSDocInfo(doc)), 
                        requestData.getSigVerCrypto()
                    );
            } catch (WSSecurityException ex) {
                LOG.debug("Error in getting KeyInfo from SAML Response: " + ex.getMessage(), ex);
                throw ex;
            }
        }
        if (samlKeyInfo == null) {
            LOG.debug("No KeyInfo supplied in the SAMLResponse signature");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        
        // Validate Signature against profiles
        validateSignatureAgainstProfiles(signature, samlKeyInfo);

        // Now verify trust on the signature
        Credential trustCredential = new Credential();
        trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
        trustCredential.setCertificates(samlKeyInfo.getCerts());

        FedizSignatureTrustValidator trustValidator = new FedizSignatureTrustValidator();
        
        boolean trusted = false;
        
        List<TrustedIssuer> trustedIssuers = config.getTrustedIssuers();
        for (TrustedIssuer ti : trustedIssuers) {
            Pattern subjectConstraint = ti.getCompiledSubject();
            List<Pattern> subjectConstraints = new ArrayList<>(1);
            if (subjectConstraint != null) {
                subjectConstraints.add(subjectConstraint);
            }
            
            if (ti.getCertificateValidationMethod().equals(CertificateValidationMethod.CHAIN_TRUST)) {
                trustValidator.setSubjectConstraints(subjectConstraints);
                trustValidator.setSignatureTrustType(TRUST_TYPE.CHAIN_TRUST_CONSTRAINTS);
            } else if (ti.getCertificateValidationMethod().equals(CertificateValidationMethod.PEER_TRUST)) {
                trustValidator.setSignatureTrustType(TRUST_TYPE.PEER_TRUST);
            } else {
                throw new IllegalStateException("Unsupported certificate validation method: " 
                                                + ti.getCertificateValidationMethod());
            }
            try {
                for (TrustManager tm: config.getCertificateStores()) {
                    try {
                        requestData.setSigVerCrypto(tm.getCrypto());
                        trustValidator.validate(trustCredential, requestData);
                        trusted = true;
                        break;
                    } catch (Exception ex) {
                        LOG.debug("Issuer '{}' not validated in keystore '{}'",
                                  ti.getName(), tm.getName());
                    }
                }
                if (trusted) {
                    break;
                }
                
            } catch (Exception ex) {
                LOG.info("Error in validating signature on SAML Response: " + ex.getMessage(), ex);
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }
        }
        
        if (!trusted) {
            LOG.warn("SAML Response is not trusted");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }
    
    /**
     * Validate a signature against the profiles
     */
    private void validateSignatureAgainstProfiles(
        Signature signature, 
        SAMLKeyInfo samlKeyInfo
    ) throws WSSecurityException {
        // Validate Signature against profiles
        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        try {
            validator.validate(signature);
        } catch (ValidationException ex) {
            LOG.debug("Error in validating the SAML Signature: " + ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        BasicX509Credential credential = new BasicX509Credential();
        if (samlKeyInfo.getCerts() != null) {
            credential.setEntityCertificate(samlKeyInfo.getCerts()[0]);
        } else if (samlKeyInfo.getPublicKey() != null) {
            credential.setPublicKey(samlKeyInfo.getPublicKey());
        } else {
            LOG.debug("Can't get X509Certificate or PublicKey to verify signature");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        SignatureValidator sigValidator = new SignatureValidator(credential);
        try {
            sigValidator.validate(signature);
        } catch (ValidationException ex) {
            LOG.debug("Error in validating the SAML Signature: " + ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
    }
    
}
