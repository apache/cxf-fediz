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

package org.apache.cxf.fediz.spring.preauth;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.FederationPrincipal;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on the
 * J2EE container-based authentication mechanism. It will use the J2EE user
 * principal name as the pre-authenticated principal and the WS-Federation signin request
 * as the credentials.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class FederationPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final String SECURITY_TOKEN_ATTR = "org.apache.fediz.SECURITY_TOKEN";
        
    /**
     * Return the J2EE user name.
     */
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
        Object principal = httpRequest.getUserPrincipal();
        if (logger.isDebugEnabled()) {
            logger.debug("PreAuthenticated J2EE principal: "
                         + httpRequest.getUserPrincipal() == null ? null : httpRequest.getUserPrincipal().getName());
        }
        return principal;
    }

    /**
     * For J2EE container-based authentication there is no generic way to
     * retrieve the credentials, as such this method returns a fixed dummy
     * value.
     */
    protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
        Object principal = httpRequest.getUserPrincipal() == null ? null : httpRequest.getUserPrincipal();
        if (principal instanceof FederationPrincipal) {
            Object obj = httpRequest.getSession(false).getAttribute(SECURITY_TOKEN_ATTR);
            if (obj != null)  {
                return obj;
            } else {
                logger.error("Session must contain Federation response");
                throw new IllegalStateException("Session must contain Federation response");
            }
        } else {
            logger.error("Principal must be instance of FederationPrincipal: " + principal.toString());
            throw new IllegalStateException("Principal must be instance of FederationPrincipal");
        }
        //return "N/A";
    }
}
