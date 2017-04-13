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

package org.apache.cxf.fediz.spring.web;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.apache.cxf.fediz.spring.authentication.ExpiredTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

/**
 * A AuthenticationFailureHandler which will redirect a expired user (token) back to the IdP.
 */
public class FederationAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final Logger LOG = LoggerFactory.getLogger(FederationAuthenticationFailureHandler.class);

    private FederationConfig federationConfig;

    public FederationAuthenticationFailureHandler() {
        super();
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        if (exception instanceof ExpiredTokenException) {
            String redirectUrl = null;
            try {
                FedizContext fedContext = federationConfig.getFedizContext();
                FedizProcessor wfProc =
                    FedizProcessorFactory.newFedizProcessor(fedContext.getProtocol());
                RedirectionResponse redirectionResponse =
                    wfProc.createSignInRequest(request, fedContext);
                redirectUrl = redirectionResponse.getRedirectionURL();

                if (redirectUrl == null) {
                    LOG.warn("Failed to create SignInRequest. Redirect URL null");
                    throw new ServletException("Failed to create SignInRequest. Redirect URL null");
                }

                Map<String, String> headers = redirectionResponse.getHeaders();
                if (!headers.isEmpty()) {
                    for (Entry<String, String> entry : headers.entrySet()) {
                        response.addHeader(entry.getKey(), entry.getValue());
                    }
                }

            } catch (ProcessingException ex) {
                LOG.warn("Failed to create SignInRequest", ex);
                throw new ServletException("Failed to create SignInRequest: " + ex.getMessage());
            }

            if (LOG.isInfoEnabled()) {
                LOG.info("Redirecting to IDP: " + redirectUrl);
            }
            response.sendRedirect(redirectUrl);
        }

        super.onAuthenticationFailure(request, response, exception);
    }

    public FederationConfig getFederationConfig() {
        return federationConfig;
    }

    public void setFederationConfig(FederationConfig fedConfig) {
        this.federationConfig = fedConfig;
    }

}