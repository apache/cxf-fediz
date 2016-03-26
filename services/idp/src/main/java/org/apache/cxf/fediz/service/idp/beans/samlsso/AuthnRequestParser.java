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

import java.io.InputStream;
import java.io.InputStreamReader;

import org.w3c.dom.Document;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Parse the received SAMLRequest into an OpenSAML AuthnRequest
 */
@Component
public class AuthnRequestParser {

    private static final Logger LOG = LoggerFactory.getLogger(AuthnRequestParser.class);

    public void parseSAMLRequest(RequestContext context, Idp idp, String samlRequest) throws ProcessingException {
        LOG.debug("Received SAML Request: {}", samlRequest);

        AuthnRequest parsedRequest = null;
        if (samlRequest == null) {
            WebUtils.removeAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
        } else {
            parsedRequest = 
                (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
            if (parsedRequest == null) {
                try {
                    parsedRequest = extractRequest(samlRequest);
                    WebUtils.putAttributeInFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST, parsedRequest);
                    LOG.debug("SAML Request with id '{}' successfully parsed", parsedRequest.getID());
                } catch (Exception ex) {
                    LOG.warn("Error parsing request: {}", ex.getMessage());
                }
            }
        }
    }
    
    public String retrieveRealm(RequestContext context) {
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
        if (authnRequest != null && authnRequest.getIssuer() != null) {
            String issuer = authnRequest.getIssuer().getValue();
            LOG.debug("Parsed SAML AuthnRequest Issuer: {}", issuer);
            return issuer;
        }
        
        LOG.debug("No AuthnRequest available to be parsed");
        return null;
    }
    
    public String retrieveConsumerURL(RequestContext context) {
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);

        if (authnRequest != null && authnRequest.getAssertionConsumerServiceURL() != null) {
            String consumerURL = authnRequest.getAssertionConsumerServiceURL();
            LOG.debug("Parsed SAML AuthnRequest Consumer URL: {}", consumerURL);
            return consumerURL;
        }
        
        LOG.debug("No AuthnRequest available to be parsed");
        return null;
    }
    
    public String retrieveRequestId(RequestContext context) {
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);

        if (authnRequest != null && authnRequest.getID() != null) {
            String id = authnRequest.getID();
            LOG.debug("Parsed SAML AuthnRequest Id: {}", id);
            return id;
        }
        
        LOG.debug("No AuthnRequest available to be parsed");
        return null;
    }
    
    public String retrieveRequestIssuer(RequestContext context) {
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);

        if (authnRequest != null && authnRequest.getIssuer() != null) {
            String issuer = authnRequest.getIssuer().getValue();
            LOG.debug("Parsed SAML AuthnRequest Issuer: {}", issuer);
            return issuer;
        }
        
        LOG.debug("No AuthnRequest available to be parsed");
        return null;
    }
    
    public boolean isForceAuthentication(RequestContext context) {
        AuthnRequest authnRequest = 
            (AuthnRequest)WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
        if (authnRequest != null) {
            return authnRequest.isForceAuthn().booleanValue();
        }
        
        LOG.debug("No AuthnRequest available to be parsed");
        return false;
    }
    
    private AuthnRequest extractRequest(String samlRequest) throws Exception {
        byte[] deflatedToken = Base64Utility.decode(samlRequest);
        InputStream tokenStream = new DeflateEncoderDecoder().inflateToken(deflatedToken);

        Document responseDoc = StaxUtils.read(new InputStreamReader(tokenStream, "UTF-8"));
        AuthnRequest request = 
            (AuthnRequest)OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        if (LOG.isDebugEnabled()) {
            LOG.debug(DOM2Writer.nodeToString(responseDoc));
        }
        return request;
    }
    
}
