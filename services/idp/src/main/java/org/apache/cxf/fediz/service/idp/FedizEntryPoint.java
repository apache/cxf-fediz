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

package org.apache.cxf.fediz.service.idp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.service.ConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;


/**
 * Used by the <code>ExceptionTranslationFilter</code> to commence authentication
 * <p>
 * The user's browser will be redirected to the IDP.
 *
 */
public class FedizEntryPoint implements AuthenticationEntryPoint,
    InitializingBean, ApplicationContextAware {
    
    private static final Logger LOG = LoggerFactory.getLogger(FedizEntryPoint.class);
    
    private ApplicationContext appContext;
    private ConfigService configService;
    private String realm;
    private Idp idpConfig;

    public ConfigService getConfigService() {
        return configService;
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }
    
    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }
    
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.appContext, "ApplicationContext cannot be null.");
        Assert.notNull(this.configService, "ConfigService cannot be null.");
        Assert.notNull(this.realm, "realm cannot be null.");
    }

    public final void commence(final HttpServletRequest servletRequest, final HttpServletResponse response,
            final AuthenticationException authenticationException) throws IOException, ServletException {

        idpConfig = configService.getIDP(realm);
        Assert.notNull(this.idpConfig, "idpConfig cannot be null. Check realm and config service implementation");
        
        String redirectUrl = null;
        String wauth = servletRequest.getParameter(FederationConstants.PARAM_AUTH_TYPE);
        if (wauth == null) {
            wauth = "default";
        }
        String loginUri = idpConfig.getAuthenticationURIs().get(wauth);
        if (loginUri == null) {
            LOG.warn("wauth value '" + wauth + "' not supported");
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "The wauth value that was supplied is not supported");
            return;
        }
        redirectUrl = new StringBuilder(extractFullContextPath(servletRequest))
            .append(loginUri).append("?").append(servletRequest.getQueryString()).toString();
        
        preCommence(servletRequest, response);
        if (LOG.isInfoEnabled()) {
            LOG.info("Redirect to " + redirectUrl);
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
    
    protected String extractFullContextPath(HttpServletRequest request) throws MalformedURLException {
        String result = null;
        String contextPath = request.getContextPath();
        String requestUrl = request.getRequestURL().toString();
        
        String requestPath = new URL(requestUrl).getPath();
        // Cut request path of request url and add context path if not ROOT
        if (requestPath != null && requestPath.length() > 0) {
            int lastIndex = requestUrl.lastIndexOf(requestPath);
            result = requestUrl.substring(0, lastIndex);
        } else {
            result = requestUrl;
        }
        if (contextPath != null && contextPath.length() > 0) {
            // contextPath contains starting slash
            result = result + contextPath;
        }
        if (result.charAt(result.length() - 1) != '/') {
            result = result + "/";
        }
        return result;
    }



}
