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
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.apache.cxf.fediz.spring.authentication.ExpiredTokenException;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.context.SecurityContext;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;


public class FederationAuthenticationFilter extends AbstractProcessingFilter {
    
    private static final Logger LOG = LoggerFactory.getLogger(FederationAuthenticationFilter.class);
                                                              
    private FederationConfig federationConfig;
    
    public FederationAuthenticationFilter() {
        super();
    }

    /**
     * 
     */
    @Override
    protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        boolean result = request.getRequestURI().contains(getFilterProcessesUrl());
        result |= isTokenExpired();
        if (logger.isDebugEnabled()) {
            logger.debug("requiresAuthentication = " + result);
        }
        return result;
    }
    
    private boolean isTokenExpired() {
        SecurityContext context = SecurityContextHolder.getContext();
        boolean detectExpiredTokens = 
            federationConfig != null && federationConfig.getFedizContext().isDetectExpiredTokens();
        if (context != null && detectExpiredTokens) {
            Authentication authentication = context.getAuthentication();
            if (authentication instanceof FederationAuthenticationToken) {
                Date tokenExpires = 
                    ((FederationAuthenticationToken)authentication).getResponse().getTokenExpires();
                if (tokenExpires == null) {
                    return false;
                }

                Date currentTime = new Date();
                if (currentTime.after(tokenExpires)) {
                    return true;
                }
            }
        }
            
        return false;
    }

    @Override
    public int getOrder() {
        return FilterChainOrder.BASIC_PROCESSING_FILTER;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        
        if (isTokenExpired()) {
            throw new ExpiredTokenException("Token is expired");
        }
        
        verifySavedState(request);
        
        String wa = request.getParameter(FederationConstants.PARAM_ACTION);
        String responseToken = getResponseToken(request);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(wa);
        wfReq.setResponseToken(responseToken);
        wfReq.setState(request.getParameter(SAMLSSOConstants.RELAY_STATE));
        wfReq.setRequest(request);
        
        X509Certificate certs[] = 
            (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
        wfReq.setCerts(certs);
        
        final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(null, wfReq);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }
    
    private void verifySavedState(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String savedContext = (String)session.getAttribute(FederationAuthenticationEntryPoint.SAVED_CONTEXT);
            String state = getState(request);
            if (savedContext != null && !savedContext.equals(state)) {
                logger.warn("The received state does not match the state saved in the context");
                throw new BadCredentialsException("The received state does not match the state saved in the context");
            }
        }
    }
    
    private String getState(ServletRequest request) {
        if (request.getParameter(FederationConstants.PARAM_CONTEXT) != null) {
            return request.getParameter(FederationConstants.PARAM_CONTEXT);
        } else if (request.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return request.getParameter(SAMLSSOConstants.RELAY_STATE);
        }
        
        return null;
    }
    
    @Override
    public void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                             AuthenticationException authException) {
        if (authException instanceof ExpiredTokenException) {
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
                    throw new BadCredentialsException("Failed to create SignInRequest. Redirect URL null");
                }
                
                Map<String, String> headers = redirectionResponse.getHeaders();
                if (!headers.isEmpty()) {
                    for (Entry<String, String> entry : headers.entrySet()) {
                        response.addHeader(entry.getKey(), entry.getValue());
                    }
                }
                
            } catch (ProcessingException ex) {
                LOG.warn("Failed to create SignInRequest", ex);
                throw new BadCredentialsException("Failed to create SignInRequest: " + ex.getMessage());
            }
            
            if (LOG.isInfoEnabled()) {
                LOG.info("Redirecting to IDP: " + redirectUrl);
            }
            try {
                response.sendRedirect(redirectUrl);
            } catch (IOException ex) {
                throw new BadCredentialsException(ex.getMessage(), ex);
            }
        }
        
        try {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (IOException e) {
            throw authException;
        }
    }
    
    private String getResponseToken(ServletRequest request) {
        if (request.getParameter(FederationConstants.PARAM_RESULT) != null) {
            return request.getParameter(FederationConstants.PARAM_RESULT);
        } else if (request.getParameter(SAMLSSOConstants.SAML_RESPONSE) != null) {
            return request.getParameter(SAMLSSOConstants.SAML_RESPONSE);
        }
        
        return null;
    }

    @Override
    public String getDefaultFilterProcessesUrl() {
        return "/j_spring_fediz_security_check";
    }

    public FederationConfig getFederationConfig() {
        return federationConfig;
    }

    public void setFederationConfig(FederationConfig fedConfig) {
        this.federationConfig = fedConfig;
    }

}