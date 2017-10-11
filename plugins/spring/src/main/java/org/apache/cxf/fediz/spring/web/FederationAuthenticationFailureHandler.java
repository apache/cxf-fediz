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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.spring.FederationConfig;
import org.apache.cxf.fediz.spring.authentication.ExpiredTokenException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

/**
 * A AuthenticationFailureHandler which will redirect a expired user (token) back to the IdP.
 */
public class FederationAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private FederationConfig federationConfig;
    
    public FederationAuthenticationFailureHandler() {
        super();
    }
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        
        if (exception instanceof ExpiredTokenException) {
            // Just redirect back to the original URL and re-start the authentication process.
            response.sendRedirect(request.getRequestURL().toString());
            return;
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
