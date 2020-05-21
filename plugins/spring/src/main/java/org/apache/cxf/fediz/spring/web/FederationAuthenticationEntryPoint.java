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
import javax.servlet.http.HttpSession;

import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.handler.RequestHandler;
import org.apache.cxf.fediz.core.metadata.MetadataDocumentHandler;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;


/**
 * Used by the <code>ExceptionTranslationFilter</code> to commence authentication via the
 * WS-Federation protocol.
 * <p>
 * The user's browser will be redirected to the IDP.
 *
 */
public class FederationAuthenticationEntryPoint implements AuthenticationEntryPoint,
    InitializingBean, ApplicationContextAware {

    /**
     * The key used to save the context of the request
     */
    public static final String SAVED_CONTEXT = "SAVED_CONTEXT";

    private static final Logger LOG = LoggerFactory.getLogger(FederationAuthenticationEntryPoint.class);

    private ApplicationContext appContext;
    private FederationConfig federationConfig;
    private RequestHandler<?> requestHandler;

    public RequestHandler<?> getRequestHandler() {
        return requestHandler;
    }

    public void setRequestHandler(RequestHandler<?> requestHandler) {
        this.requestHandler = requestHandler;
    }

    public FederationConfig getFederationConfig() {
        return federationConfig;
    }

    public void setFederationConfig(FederationConfig federationConfig) {
        this.federationConfig = federationConfig;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.appContext, "ApplicationContext cannot be null.");
        Assert.notNull(this.federationConfig, "FederationConfig cannot be null.");
    }

    public void commence(final HttpServletRequest servletRequest, final HttpServletResponse response,
            final AuthenticationException authenticationException) throws IOException, ServletException {

        FedizContext fedContext = federationConfig.getFedizContext();
        LOG.debug("Federation context: {}", fedContext);

        // First see if we want to handle the request in some custom way
        if (requestHandler != null && requestHandler.canHandleRequest(servletRequest)) {
            requestHandler.handleRequest(servletRequest, response);
            return;
        }

        // Check to see if it is a metadata request
        MetadataDocumentHandler mdHandler = new MetadataDocumentHandler(fedContext);
        if (mdHandler.canHandleRequest(servletRequest)) {
            mdHandler.handleRequest(servletRequest, response);
            return;
        }

        String redirectUrl = null;
        try {
            FedizProcessor wfProc =
                FedizProcessorFactory.newFedizProcessor(fedContext.getProtocol());
            RedirectionResponse redirectionResponse =
                wfProc.createSignInRequest(servletRequest, fedContext);
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

            HttpSession session = servletRequest.getSession(true);
            session.setAttribute(SAVED_CONTEXT, redirectionResponse.getRequestState());
        } catch (ProcessingException ex) {
            LOG.warn("Failed to create SignInRequest", ex);
            throw new ServletException("Failed to create SignInRequest: " + ex.getMessage());
        }

        preCommence(servletRequest, response);
        if (LOG.isInfoEnabled()) {
            LOG.info("Redirecting to IDP: " + redirectUrl);
        }
        response.sendRedirect(redirectUrl);
    }

    /**
     * Template method for you to do your own pre-processing before the redirect occurs.
     *
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     */
    protected void preCommence(final HttpServletRequest request, final HttpServletResponse response) {

    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.appContext = applicationContext;
    }

}
