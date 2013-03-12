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

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.FederationProcessor;
import org.apache.cxf.fediz.core.FederationProcessorImpl;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.spring.FederationConfig;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AuthenticationEntryPoint;
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
    
    private static final Logger LOG = LoggerFactory.getLogger(FederationAuthenticationEntryPoint.class);
    
    private ApplicationContext appContext;
    private FederationConfig federationConfig;
    //private String servletContext;

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

    public final void commence(final HttpServletRequest servletRequest, final HttpServletResponse response,
            final AuthenticationException authenticationException) throws IOException, ServletException {

        String redirectUrl = null;
        FederationContext fedContext = federationConfig.getFederationContext();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Federation context: " + fedContext);
        }
        try {
            FederationProcessor wfProc = new FederationProcessorImpl();
            redirectUrl = wfProc.createSignInRequest(servletRequest, fedContext);
            if (redirectUrl == null) {
                LOG.warn("Failed to create SignInRequest.");
                response.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
            }
        } catch (ProcessingException ex) {
            System.err.println("Failed to create SignInRequest: " + ex.getMessage());
            LOG.warn("Failed to create SignInRequest: " + ex.getMessage());
            response.sendError(
                               HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
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
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.appContext = applicationContext;
    }

    @Override
    public void commence(ServletRequest request, ServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        
        HttpServletRequest hrequest = (HttpServletRequest)request;
        HttpServletResponse hresponse = (HttpServletResponse)response;
        String redirectUrl = null;
        FederationContext fedContext = federationConfig.getFederationContext();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Federation context: " + fedContext);
        }
        try {
            FederationProcessor wfProc = new FederationProcessorImpl();
            redirectUrl = wfProc.createSignInRequest(hrequest, fedContext);
            if (redirectUrl == null) {
                LOG.warn("Failed to create SignInRequest.");
                hresponse.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
            }
        } catch (ProcessingException ex) {
            System.err.println("Failed to create SignInRequest: " + ex.getMessage());
            LOG.warn("Failed to create SignInRequest: " + ex.getMessage());
            hresponse.sendError(
                               HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
        }
        
        preCommence(hrequest, hresponse);
        if (LOG.isInfoEnabled()) {
            LOG.info("Redirecting to IDP: " + redirectUrl);
        }
        hresponse.sendRedirect(redirectUrl);
        
    }

    /*
    public void setServletContext(String servletContext) {
        this.servletContext = servletContext;
    }

    public String getServletContext() {
        return servletContext;
    }
    */

}
