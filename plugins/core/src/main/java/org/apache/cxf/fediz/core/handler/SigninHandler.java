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
package org.apache.cxf.fediz.core.handler;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * It is recommended to extend this class and implement the resumeRequest method to continue invoking the originally
 * requested website.
 */
public class SigninHandler<T> implements RequestHandler<T> {

    private static final Logger LOG = LoggerFactory.getLogger(SigninHandler.class);
    private final FedizContext fedizContext;

    public SigninHandler(FedizContext fedizContext) {
        this.fedizContext = fedizContext;
    }

    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        if (fedizContext.getProtocol() instanceof FederationProtocol
            && FederationConstants.ACTION_SIGNIN.equals(request.getParameter(FederationConstants.PARAM_ACTION))) {
            return true;
        } else if (fedizContext.getProtocol() instanceof SAMLProtocol
                   && request.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return true;
        }
        return false;
    }

    @Override
    public T handleRequest(HttpServletRequest request, HttpServletResponse response) {
        if (request.getMethod().equals("POST")) {
            LOG.debug("Sign-In-Response received");
            String responseToken = getResponseToken(request);
            if (responseToken != null) {
                LOG.debug("Validating RSTR...");
                // process and validate the token
                try {
                    FedizResponse federationResponse = processSigninRequest(responseToken, request, response);
                    if (!validateAudienceRestrictions(federationResponse.getAudience(),
                        request.getRequestURL().toString())) {
                        return null;
                    }
                    LOG.debug("RSTR validated successfully");
                    return createPrincipal(request, response, federationResponse);
                } catch (ProcessingException e) {
                    LOG.error("Federation processing failed: " + e.getMessage());
                }
            }
        } else {
            throw new RuntimeException("Incorrect method GET for Sign-In-Response");
        }
        return null;
    }

    protected T createPrincipal(HttpServletRequest request, HttpServletResponse response,
                              FedizResponse federationResponse) {
        return null;
    }

    public FedizResponse processSigninRequest(String responseToken, HttpServletRequest req, HttpServletResponse resp)
        throws ProcessingException {
        LOG.debug("Process SignIn request");
        LOG.debug("token=\n{}", responseToken);
        
        FedizRequest federationRequest = new FedizRequest();

        String wa = req.getParameter(FederationConstants.PARAM_ACTION);

        federationRequest.setAction(wa);
        federationRequest.setResponseToken(responseToken);
        federationRequest.setState(req.getParameter("RelayState"));
        federationRequest.setRequest(req);
        federationRequest.setCerts((X509Certificate[])req.getAttribute("javax.servlet.request.X509Certificate"));

        FedizProcessor processor = FedizProcessorFactory.newFedizProcessor(fedizContext.getProtocol());
        return processor.processRequest(federationRequest, fedizContext);
    }

    protected boolean validateAudienceRestrictions(String audience, String requestURL) {
        // Validate the AudienceRestriction in Security Token (e.g. SAML)
        // validate against the configured list of audienceURIs
        List<String> audienceURIs = fedizContext.getAudienceUris();
        boolean validAudience = audienceURIs.isEmpty() && audience == null;
        if (!validAudience && audience != null) {
            
            for (String a : audienceURIs) {
                if (audience.startsWith(a)) {
                    validAudience = true;
                    LOG.debug("Token audience matches with valid URIs.");
                    break;
                }
            }
            
            if (!validAudience) {
                LOG.warn("Token AudienceRestriction [{}] doesn't match with specified list of URIs.", audience);
                LOG.debug("Authenticated URIs are: {}", audienceURIs);
            }
            
            if (LOG.isDebugEnabled() && requestURL != null && requestURL.indexOf(audience) == -1) {
                LOG.debug("Token AudienceRestriction doesn't match with request URL [{}]  [{}]", audience, requestURL);
            }
        }
        return validAudience;
    }

    public String getResponseToken(HttpServletRequest request) {
        String token = null;
        if (fedizContext.getProtocol() instanceof FederationProtocol) {
            token = request.getParameter(FederationConstants.PARAM_RESULT);
            if (token == null) {
                new RuntimeException("Missing required parameter 'wresult'");
            }
        } else if (fedizContext.getProtocol() instanceof SAMLProtocol) {
            token = request.getParameter(SAMLSSOConstants.SAML_RESPONSE);
            if (token == null) {
                new RuntimeException("Missing required parameter 'SAMLResponse'");
            }
        }
        return token;
    }

    public FedizContext getFedizContext() {
        return fedizContext;
    }
}
