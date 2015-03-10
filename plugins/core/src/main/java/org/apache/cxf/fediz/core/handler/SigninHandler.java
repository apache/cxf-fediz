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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FederationProcessorImpl;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
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
    protected final FedizContext fedizConfig;

    public SigninHandler(FedizContext fedConfig) {
        this.fedizConfig = fedConfig;
    }

    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        return FederationConstants.ACTION_SIGNIN.equals(request.getParameter(FederationConstants.PARAM_ACTION));
    }

    @Override
    public T handleRequest(HttpServletRequest request, HttpServletResponse response) {
        if (request.getMethod().equals("POST")) {
            LOG.debug("Sign-In-Response received");
            String wresult = request.getParameter(FederationConstants.PARAM_RESULT);
            if (wresult != null) {
                LOG.debug("Validating RSTR...");
                // process and validate the token
                try {
                    FedizResponse federationResponse = processSigninRequest(request, response);
                    LOG.debug("RSTR validated successfully");
                    T principal = createPrincipal(request, response, federationResponse);
                    resumeRequest(request, response, federationResponse);
                    return principal;
                } catch (ProcessingException e) {
                    LOG.error("RSTR validated failed.");
                }
            } else {
                throw new RuntimeException("Missing required parameter 'wresult'");
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

    protected void resumeRequest(HttpServletRequest request, HttpServletResponse response,
        FedizResponse federationResponse) {
    }

    public FedizResponse processSigninRequest(HttpServletRequest req, HttpServletResponse resp)
        throws ProcessingException {
        FedizRequest federationRequest = new FedizRequest();

        String wa = req.getParameter(FederationConstants.PARAM_ACTION);
        String responseToken = getResponseToken(req, fedizConfig);

        federationRequest.setAction(wa);
        federationRequest.setResponseToken(responseToken);
        federationRequest.setState(req.getParameter("RelayState"));
        federationRequest.setRequest(req);

        FedizProcessor processor = new FederationProcessorImpl();
        return processor.processRequest(federationRequest, fedizConfig);
    }

    public String getResponseToken(HttpServletRequest request, FedizContext fedConfig) {
        if (fedConfig.getProtocol() instanceof FederationProtocol) {
            return request.getParameter(FederationConstants.PARAM_RESULT);
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol) {
            return request.getParameter(SAMLSSOConstants.SAML_RESPONSE);
        }
        return null;
    }
}
