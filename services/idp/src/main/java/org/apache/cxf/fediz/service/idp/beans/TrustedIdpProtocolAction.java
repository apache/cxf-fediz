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
package org.apache.cxf.fediz.service.idp.beans;

import java.net.URL;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.protocols.ProtocolController;
import org.apache.cxf.fediz.service.idp.spi.TrustedIdpProtocolHandler;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to clear security context and invalidate IDP session.
 */
@Component
public class TrustedIdpProtocolAction {

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpProtocolAction.class);
    
    private static final String IDP_CONFIG = "idpConfig";
    
    @Autowired
    // Qualifier workaround. See http://www.jayway.com/2013/11/03/spring-and-autowiring-of-generic-types/
    @Qualifier("trustedIdpProtocolControllerImpl")
    private ProtocolController<TrustedIdpProtocolHandler> trustedIdpProtocolHandlers;
    
    public String mapSignInRequest(RequestContext requestContext) {
        String trustedIdpRealm = requestContext.getFlowScope().getString("whr");
        LOG.info("Prepare redirect to Trusted IDP '{}'", trustedIdpRealm);
        
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(requestContext, IDP_CONFIG);
        
        TrustedIdp trustedIdp = idpConfig.findTrustedIdp(trustedIdpRealm);
        if (trustedIdp == null) {
            LOG.error("TrustedIdp '{}' not configured", trustedIdpRealm);
            throw new IllegalStateException("TrustedIdp '" + trustedIdpRealm + "'");
        }
        
        String protocol = trustedIdp.getProtocol();
        LOG.debug("TrustedIdp '{}' supports protocol {}", trustedIdpRealm, protocol);
        
        TrustedIdpProtocolHandler protocolHandler = trustedIdpProtocolHandlers.getProtocolHandler(protocol);
        if (protocolHandler == null) {
            LOG.error("No ProtocolHandler found for {}", protocol);
            throw new IllegalStateException("No ProtocolHandler found for '" + protocol + "'");
        }
        URL redirectUrl = protocolHandler.mapSignInRequest(requestContext, idpConfig, trustedIdp);
        LOG.info("Redirect url {}", redirectUrl.toString());
        return redirectUrl.toString();
    }
    
    public String processSignInResponse(RequestContext requestContext) {
        String trustedIdpRealm = requestContext.getFlowScope().getString("whr");
        
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(requestContext, IDP_CONFIG);
        
        TrustedIdp trustedIdp = idpConfig.findTrustedIdp(trustedIdpRealm);
        if (trustedIdp == null) {
            LOG.error("TrustedIdp '{}' not configured", trustedIdpRealm);
            throw new IllegalStateException("TrustedIdp '" + trustedIdpRealm + "'");
        }
        
        String protocol = trustedIdp.getProtocol();
        LOG.debug("TrustedIdp '{}' supports protocol {}", trustedIdpRealm, protocol);
        
        TrustedIdpProtocolHandler protocolHandler = trustedIdpProtocolHandlers.getProtocolHandler(protocol);
        if (protocolHandler == null) {
            LOG.error("No ProtocolHandler found for {}", protocol);
            throw new IllegalStateException("No ProtocolHandler found for '" + protocol + "'");
        }
        URL redirectUrl = protocolHandler.processSignInResponse(requestContext, idpConfig, trustedIdp);
        LOG.info("Redirect required? {}", (redirectUrl != null));
        if (redirectUrl != null) {
            String redirectUrlStr = redirectUrl.toString();
            LOG.info("Redirect URL: {}", redirectUrlStr);
            return redirectUrlStr;
        }
        return null;
    }
    
    public SecurityToken mapSignInResponse(RequestContext requestContext) {
        String trustedIdpRealm = requestContext.getFlowScope().getString("whr");
        LOG.info("Prepare validate SignInResponse of Trusted IDP '{}'", trustedIdpRealm);
        
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(requestContext, IDP_CONFIG);
        
        TrustedIdp trustedIdp = idpConfig.findTrustedIdp(trustedIdpRealm);
        if (trustedIdp == null) {
            LOG.error("TrustedIdp '{}' not configured", trustedIdpRealm);
            throw new IllegalStateException("TrustedIdp '" + trustedIdpRealm + "'");
        }
        
        String protocol = trustedIdp.getProtocol();
        LOG.debug("TrustedIdp '{}' supports protocol {}", trustedIdpRealm, protocol);
        
        TrustedIdpProtocolHandler protocolHandler = trustedIdpProtocolHandlers.getProtocolHandler(protocol);
        if (protocolHandler == null) {
            LOG.error("No ProtocolHandler found for {}", protocol);
            throw new IllegalStateException("No ProtocolHandler found for '" + protocol + "'");
        }
        SecurityToken token = protocolHandler.mapSignInResponse(requestContext, idpConfig, trustedIdp);
        if (token != null) {
            LOG.info("SignInResponse successfully validated and SecurityToken created");
        }
        return token;
    }
}
