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
import java.io.PrintWriter;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.apache.wss4j.common.util.DOM2Writer;

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

    private String getMetadataURI(FedizContext fedConfig) {
        if (fedConfig.getProtocol().getMetadataURI() != null) {
            return fedConfig.getProtocol().getMetadataURI();
        } else if (fedConfig.getProtocol() instanceof FederationProtocol) {
            return FederationConstants.METADATA_PATH_URI;
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol) {
            return SAMLSSOConstants.FEDIZ_SAML_METADATA_PATH_URI;
        }
        
        return FederationConstants.METADATA_PATH_URI;
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
        FedizContext fedContext = federationConfig.getFedizContext();
        LOG.debug("Federation context: {}", fedContext);
        
        if (hrequest.getRequestURL().indexOf(FederationConstants.METADATA_PATH_URI) != -1
            || hrequest.getRequestURL().indexOf(getMetadataURI(fedContext)) != -1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Metadata document requested");
            }
            response.setContentType("text/xml");
            PrintWriter out = response.getWriter();
            
            FedizProcessor wfProc = 
                FedizProcessorFactory.newFedizProcessor(fedContext.getProtocol());
            try {
                Document metadata = wfProc.getMetaData(hrequest, fedContext);
                out.write(DOM2Writer.nodeToString(metadata));
                return;
            } catch (Exception ex) {
                LOG.warn("Failed to get metadata document: " + ex.getMessage());
                hresponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }            
        }
        
        String redirectUrl = null;
        try {
            FedizProcessor wfProc = 
                FedizProcessorFactory.newFedizProcessor(fedContext.getProtocol());
            
            RedirectionResponse redirectionResponse =
                wfProc.createSignInRequest(hrequest, fedContext);
            redirectUrl = redirectionResponse.getRedirectionURL();
            
            if (redirectUrl == null) {
                LOG.warn("Failed to create SignInRequest.");
                hresponse.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
            }
            
            Map<String, String> headers = redirectionResponse.getHeaders();
            if (!headers.isEmpty()) {
                for (Entry<String, String> entry : headers.entrySet()) {
                    hresponse.addHeader(entry.getKey(), entry.getValue());
                }
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

}
