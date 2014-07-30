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

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;


public class FederationAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    
    public FederationAuthenticationFilter() {
        super("/j_spring_fediz_security_check");
        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
        throws AuthenticationException, IOException {

        
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
  
    private String getResponseToken(ServletRequest request) {
        if (request.getParameter(FederationConstants.PARAM_RESULT) != null) {
            return request.getParameter(FederationConstants.PARAM_RESULT);
        } else if (request.getParameter(SAMLSSOConstants.SAML_RESPONSE) != null) {
            return request.getParameter(SAMLSSOConstants.SAML_RESPONSE);
        }
        
        return null;
    }

    /**
     * 
     */
    @Override
    protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        final boolean result = request.getRequestURI().contains(getFilterProcessesUrl());
        
        if (logger.isDebugEnabled()) {
            logger.debug("requiresAuthentication = " + result);
        }
        return result;
    }


}