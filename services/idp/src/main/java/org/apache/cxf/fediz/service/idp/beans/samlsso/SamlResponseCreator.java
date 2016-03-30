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

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.samlsso.SAML2CallbackHandler;
import org.apache.cxf.fediz.service.idp.samlsso.SAML2PResponseComponentBuilder;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.WSConstants;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Insert the SAML Token received from the STS into a SAML Response
 */
@Component
public class SamlResponseCreator {

    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseCreator.class);
    private boolean supportDeflateEncoding = true;

    public String createSAMLResponse(RequestContext context, Idp idp, Element rpToken,
                                     String consumerURL, String requestId, String requestIssuer) 
                                         throws ProcessingException {
        List<Element> samlTokens = 
            DOMUtils.findAllElementsByTagNameNS(rpToken, WSConstants.SAML2_NS, "Assertion");
        if (samlTokens.isEmpty() || samlTokens.size() != 1) {
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
        
        try {
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(samlTokens.get(0));
            if (wrapper.getSaml2() == null) {
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
            
            String remoteAddr = WebUtils.getHttpServletRequest(context).getRemoteAddr();
            Assertion saml2Assertion = 
                createSAML2Assertion(context, idp, wrapper, requestId, requestIssuer, 
                                     remoteAddr, consumerURL);
            
            Element response = createResponse(idp, requestId, saml2Assertion);
            return encodeResponse(response);
        } catch (Exception ex) {
            LOG.warn("Error marshalling SAML Token: {}", ex.getMessage());
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
    }
    
    private Assertion createSAML2Assertion(RequestContext context, Idp idp, SamlAssertionWrapper receivedToken,
                                           String requestID, String requestIssuer, 
                                           String remoteAddr, String racs) throws Exception {
        // Create an AuthenticationAssertion
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setIssuer(idp.getRealm());
        callbackHandler.setSubject(receivedToken.getSaml2().getSubject());
        
        // Test Subject against received Subject (if applicable)
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
        if (authnRequest.getSubject() != null && authnRequest.getSubject().getNameID() != null
            && receivedToken.getSaml2().getSubject().getNameID() != null) {
            NameID receivedNameId = authnRequest.getSubject().getNameID();
            NameID issuedNameId = receivedToken.getSaml2().getSubject().getNameID();
            if (!receivedNameId.getValue().equals(issuedNameId.getValue())) {
                LOG.debug("Received NameID value of {} does not match issued value {}",
                          receivedNameId.getValue(), issuedNameId.getValue());
                throw new ProcessingException(ProcessingException.TYPE.INVALID_REQUEST);
            }
        }
        
        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(remoteAddr);
        subjectConfirmationData.setInResponseTo(requestID);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(racs);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);
        
        // Audience Restriction
        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.setAudienceURIs(Collections.singletonList(requestIssuer));
        conditions.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(conditions);
        
        // Attributes
        callbackHandler.setAttributeStatements(receivedToken.getSaml2().getAttributeStatements());
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        Crypto issuerCrypto = CertsUtils.getCryptoFromCertificate(idp.getCertificate());
        assertion.signAssertion(issuerCrypto.getDefaultX509Identifier(), idp.getCertificatePassword(), 
                                issuerCrypto, false);
        
        return assertion.getSaml2();
    }
    
    protected Element createResponse(Idp idp, String requestID, Assertion assertion) throws Exception {
        Document doc = DOMUtils.newDocument();
        
        Status status = 
            SAML2PResponseComponentBuilder.createStatus(
                "urn:oasis:names:tc:SAML:2.0:status:Success", null
            );
        Response response = 
            SAML2PResponseComponentBuilder.createSAMLResponse(requestID, idp.getRealm(), status);
        
        response.getAssertions().add(assertion);
        
        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);
        
        return policyElement;
    }

    protected String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);
        LOG.debug("Created Response: {}", responseMessage);

        if (supportDeflateEncoding) {
            DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
            byte[] deflatedBytes = encoder.deflateToken(responseMessage.getBytes("UTF-8"));

            return Base64Utility.encode(deflatedBytes);
        }
        
        return Base64Utility.encode(responseMessage.getBytes());
    }
    
    public boolean isSupportDeflateEncoding() {
        return supportDeflateEncoding;
    }

    public void setSupportDeflateEncoding(boolean supportDeflateEncoding) {
        this.supportDeflateEncoding = supportDeflateEncoding;
    }
}
