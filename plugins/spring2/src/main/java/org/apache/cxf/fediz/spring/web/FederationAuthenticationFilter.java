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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.FederationRequest;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;
//import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;


public class FederationAuthenticationFilter extends AbstractProcessingFilter {
    
    public FederationAuthenticationFilter() {
        super();
        //setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
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

    @Override
    public int getOrder() {
        return FilterChainOrder.BASIC_PROCESSING_FILTER;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        String wa = request.getParameter("wa");
        String wresult = request.getParameter("wresult");
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(wa);
        wfReq.setWresult(wresult);
        
        final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(null, wfReq);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    public String getDefaultFilterProcessesUrl() {
        return "/j_spring_fediz_security_check";
    }


}