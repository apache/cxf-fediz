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

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class FederationLogoutFilter extends LogoutFilter {

    private FederationConfig federationConfig;
    private String logoutUrl;

    public FederationLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
        super(logoutSuccessHandler, handlers);
    }

    @Required
    public void setFederationConfig(FederationConfig federationConfig) {
        this.federationConfig = federationConfig;
    }

    @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        String wa = request.getParameter(FederationConstants.PARAM_ACTION);
        if (FederationConstants.ACTION_SIGNOUT.equals(wa) || FederationConstants.ACTION_SIGNOUT_CLEANUP.equals(wa)) {
            // Default WS-Federation logout action
            return true;
        }

        if (this.logoutUrl == null) {
            String contextName = request.getContextPath();
            if (contextName == null || contextName.isEmpty()) {
                contextName = "/";
            }
            this.logoutUrl = federationConfig.getFedizContext(contextName).getLogoutURL();
        }
        if (this.logoutUrl != null && !this.logoutUrl.isEmpty()) {
            super.setLogoutRequestMatcher(new AntPathRequestMatcher(logoutUrl));
            return super.requiresLogout(request, response);
        }
        return false;
    }

    protected String getFilterProcessesUrl() {
        return this.logoutUrl;
    }
}
