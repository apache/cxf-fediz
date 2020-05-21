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
import java.time.Instant;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.apache.cxf.fediz.spring.authentication.ExpiredTokenException;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import static org.apache.cxf.fediz.spring.web.FederationAuthenticationEntryPoint.SAVED_CONTEXT;


public class FederationAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private FederationConfig federationConfig;

    public FederationAuthenticationFilter() {
        super("/j_spring_fediz_security_check");
        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
        throws IOException {

        if (isTokenExpired()) {
            throw new ExpiredTokenException("Token is expired");
        }

        RequestState savedRequestState = verifySavedState(request);

        String wa = request.getParameter(FederationConstants.PARAM_ACTION);
        String responseToken = getResponseToken(request);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(wa);
        wfReq.setResponseToken(responseToken);
        wfReq.setState(getState(request));
        wfReq.setRequest(request);
        wfReq.setRequestState(savedRequestState);

        X509Certificate[] certs =
            (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
        wfReq.setCerts(certs);

        final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(null, wfReq);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private boolean isTokenExpired() {
        SecurityContext context = SecurityContextHolder.getContext();
        boolean detectExpiredTokens =
            federationConfig != null && federationConfig.getFedizContext().isDetectExpiredTokens();
        if (context != null && detectExpiredTokens) {
            Authentication authentication = context.getAuthentication();
            if (authentication instanceof FederationAuthenticationToken) {
                Instant tokenExpires =
                    ((FederationAuthenticationToken)authentication).getResponse().getTokenExpires();
                if (tokenExpires == null) {
                    return false;
                }

                Instant currentTime = Instant.now();
                if (currentTime.isAfter(tokenExpires)) {
                    return true;
                }
            }
        }

        return false;
    }

    private String getResponseToken(ServletRequest request) {
        if (request.getParameter(FederationConstants.PARAM_RESULT) != null) {
            return request.getParameter(FederationConstants.PARAM_RESULT);
        } else if (request.getParameter(SAMLSSOConstants.SAML_RESPONSE) != null) {
            return request.getParameter(SAMLSSOConstants.SAML_RESPONSE);
        }

        return null;
    }

    private String getState(ServletRequest request) {
        if (request.getParameter(FederationConstants.PARAM_CONTEXT) != null) {
            return request.getParameter(FederationConstants.PARAM_CONTEXT);
        } else if (request.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return request.getParameter(SAMLSSOConstants.RELAY_STATE);
        }

        return null;
    }

    private RequestState verifySavedState(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        boolean enforceValidState =
            federationConfig == null || federationConfig.getFedizContext().isRequestStateValidation();

        if (enforceValidState) {
            if (session == null) {
                logger.warn("The received state does not match the state saved in the context");
                throw new BadCredentialsException("The received state does not match the state saved in the context");
            }
    
            RequestState savedRequestState = (RequestState) session.getAttribute(SAVED_CONTEXT);
            String state = getState(request);
            if (savedRequestState == null || !savedRequestState.getState().equals(state)) {
                logger.warn("The received state does not match the state saved in the context");
                throw new BadCredentialsException("The received state does not match the state saved in the context");
            }
            session.removeAttribute(SAVED_CONTEXT);
            return savedRequestState;
        }
        
        return null;
    }

    /**
     *
     */
    @Override
    protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        boolean result = isTokenExpired() || super.requiresAuthentication(request, response);
        if (logger.isDebugEnabled()) {
            logger.debug("requiresAuthentication = " + result);
        }
        return result;
    }

    public FederationConfig getFederationConfig() {
        return federationConfig;
    }

    public void setFederationConfig(FederationConfig fedConfig) {
        this.federationConfig = fedConfig;
    }

}