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
package org.apache.cxf.fediz.service.idp.beans.samlsso;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.SignatureTrustValidator;
import org.apache.wss4j.dom.validate.Validator;
import org.apache.xml.security.utils.Base64;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Validate the received AuthnRequest
 */
@Component
public class AuthnRequestValidator {

    private static final Logger LOG = LoggerFactory.getLogger(AuthnRequestValidator.class);

    public void validateAuthnRequest(RequestContext context, Idp idp, String signature,
                                     String relayState, String samlRequest, String realm) 
        throws Exception {
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
        if (authnRequest.isSigned()) {
            // Check destination
            checkDestination(context, authnRequest);
            
            // Check signature
            X509Certificate validatingCert = getValidatingCertificate(idp, realm);
            Crypto issuerCrypto = 
                new CertificateStore(Collections.singletonList(validatingCert).toArray(new X509Certificate[0]));
            validateAuthnRequestSignature(authnRequest.getSignature(), issuerCrypto);
        } else if (signature != null) {
            // Check destination
            checkDestination(context, authnRequest);
            
            // Check signature
            X509Certificate validatingCert = getValidatingCertificate(idp, realm);
            
            java.security.Signature sig = java.security.Signature.getInstance("SHA1withRSA");
            sig.initVerify(validatingCert);
            
            // Recreate request to sign
            String requestToSign = WebUtils.getHttpServletRequest(context).getRequestURL().toString() + "?";
            requestToSign += SSOConstants.RELAY_STATE + "=" + relayState;
            requestToSign += "&" + SSOConstants.SAML_REQUEST + "=" + URLEncoder.encode(samlRequest, "UTF-8");
            requestToSign += "&" + SSOConstants.SIG_ALG + "=" 
                + URLEncoder.encode(SSOConstants.RSA_SHA1, StandardCharsets.UTF_8.name());
            
            sig.update(requestToSign.getBytes(StandardCharsets.UTF_8));
            
            if (!sig.verify(Base64.decode(signature))) {
                LOG.debug("Signature validation failed");
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
        } else {
            LOG.debug("No signature is present, therefore the request is rejected");
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
        
        if (authnRequest.getIssuer() == null) {
            LOG.debug("No Issuer is present in the AuthnRequest");
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
        
        String format = authnRequest.getIssuer().getFormat();
        if (format != null
            && !"urn:oasis:names:tc:SAML:2.0:nameid-format:entity".equals(format)) {
            LOG.debug("An invalid Format attribute was received: {}", format);
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
    }
    
    private X509Certificate getValidatingCertificate(Idp idp, String realm) 
        throws Exception {
        Application serviceConfig = idp.findApplication(realm);
        if (serviceConfig == null || serviceConfig.getValidatingCertificate() == null) {
            LOG.debug("No validating certificate found for realm {}", realm);
            throw new ProcessingException(TYPE.ISSUER_NOT_TRUSTED);
        }
        
        return CertsUtils.parseX509Certificate(serviceConfig.getValidatingCertificate());
    }
    
    private void checkDestination(RequestContext context, AuthnRequest authnRequest) throws ProcessingException {
        // Check destination
        String destination = authnRequest.getDestination();
        LOG.debug("Validating destination: {}", destination);
        
        String localAddr = WebUtils.getHttpServletRequest(context).getRequestURL().toString();
        if (!localAddr.startsWith(destination)) {
            LOG.debug("The destination {} does not match the local address {}", destination, localAddr);
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
    }
    
    /**
     * Validate the AuthnRequest signature
     */
    private void validateAuthnRequestSignature(
        Signature signature,
        Crypto sigCrypto
    ) throws WSSecurityException {
        RequestData requestData = new RequestData();
        requestData.setSigVerCrypto(sigCrypto);
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        requestData.setWssConfig(wssConfig);
        // requestData.setCallbackHandler(callbackHandler);

        SAMLKeyInfo samlKeyInfo = null;

        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo != null) {
            try {
                Document doc = signature.getDOM().getOwnerDocument();
                samlKeyInfo =
                    SAMLUtil.getCredentialFromKeyInfo(
                        keyInfo.getDOM(), new WSSSAMLKeyInfoProcessor(requestData, new WSDocInfo(doc)), sigCrypto
                    );
            } catch (WSSecurityException ex) {
                LOG.debug("Error in getting KeyInfo from SAML AuthnRequest: {}", ex.getMessage(), ex);
                throw ex;
            }
        }
        
        if (samlKeyInfo == null) {
            LOG.debug("No KeyInfo supplied in the AuthnRequest signature");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // Validate Signature against profiles
        validateSignatureAgainstProfiles(signature, samlKeyInfo);

        // Now verify trust on the signature
        Credential trustCredential = new Credential();
        trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
        trustCredential.setCertificates(samlKeyInfo.getCerts());

        try {
            Validator signatureValidator = new SignatureTrustValidator();
            signatureValidator.validate(trustCredential, requestData);
        } catch (WSSecurityException e) {
            LOG.debug("Error in validating signature on SAML AuthnRequest: {}", e.getMessage(), e);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
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
        } catch (SignatureException ex) {
            LOG.debug("Error in validating the SAML Signature: {}", ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        BasicCredential credential = null;
        if (samlKeyInfo.getCerts() != null) {
            credential = new BasicX509Credential(samlKeyInfo.getCerts()[0]);
        } else if (samlKeyInfo.getPublicKey() != null) {
            credential = new BasicCredential(samlKeyInfo.getPublicKey());
        } else {
            LOG.debug("Can't get X509Certificate or PublicKey to verify signature");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        try {
            SignatureValidator.validate(signature, credential);
        } catch (SignatureException ex) {
            LOG.debug("Error in validating the SAML Signature: {}", ex.getMessage(), ex);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
    }
    
}
