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
package org.apache.cxf.fediz.service.idp.beans;

import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Check to see whether the IdP Token is expired or not
 */
@Component
public class IdpTokenExpiredAction {

    private static final Logger LOG = LoggerFactory
            .getLogger(IdpTokenExpiredAction.class);
    private boolean tokenExpirationValidation = true;

    public boolean isTokenExpired(String homeRealm, RequestContext context)
        throws Exception {

        SecurityToken idpToken =
            (SecurityToken) WebUtils.getAttributeFromExternalContext(context, homeRealm);
        if (idpToken == null) {
            return true;
        }

        if (tokenExpirationValidation && idpToken.isExpired()) {
            LOG.info("[IDP_TOKEN=" + idpToken.getId() + "] is expired.");
            return true;
        }

        return false;
    }

    public boolean isTokenExpirationValidation() {
        return tokenExpirationValidation;
    }

    /**
     * Set whether the token validation (e.g. lifetime) shall be performed on every request (true) or only
     * once at initial authentication (false). The default is "true" (note that the plugins default for this
     * configuration option is "true").
     * @param tokenExpirationValidation Whether to perform token expiration validation per request
     */
    public void setTokenExpirationValidation(boolean tokenExpirationValidation) {
        this.tokenExpirationValidation = tokenExpirationValidation;
    }

}
