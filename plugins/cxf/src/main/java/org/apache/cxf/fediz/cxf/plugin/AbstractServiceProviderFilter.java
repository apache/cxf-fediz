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
package org.apache.cxf.fediz.cxf.plugin;

import java.io.File;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.Map;
import java.util.ResourceBundle;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.xml.bind.JAXBException;

import org.apache.cxf.common.classloader.ClassLoaderUtils;
import org.apache.cxf.common.i18n.BundleUtils;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.samlsso.ResponseState;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.jaxrs.impl.HttpHeadersImpl;
import org.apache.cxf.jaxrs.impl.UriInfoImpl;
import org.apache.cxf.jaxrs.utils.HttpUtils;
import org.apache.cxf.message.Message;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@PreMatching
@Priority(Priorities.AUTHENTICATION + 1)
public abstract class AbstractServiceProviderFilter implements ContainerRequestFilter {
    
    public static final String SECURITY_CONTEXT_TOKEN = 
        "org.apache.fediz.SECURITY_TOKEN";
    protected static final ResourceBundle BUNDLE = 
        BundleUtils.getBundle(AbstractServiceProviderFilter.class);
    private static final Logger LOG = LoggerFactory.getLogger(AbstractServiceProviderFilter.class);
    
    private String webAppDomain;
    // private boolean addWebAppContext = true;
    // private boolean addEndpointAddressToContext;
    
    private FedizConfigurator configurator;
    private String configFile;
    
    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }
    
    @PostConstruct
    public synchronized void configure() throws JAXBException, MalformedURLException {
        if (configurator == null) {
            try {
                File f = new File(configFile);
                if (!f.exists()) {
                    URL url = ClassLoaderUtils.getResource(configFile, 
                                                           AbstractServiceProviderFilter.class);
                    if (url == null) {
                        url = new URL(configFile);
                    }
                    if (url != null) {
                        f = new File(url.getPath());
                    }
                }
                configurator = new FedizConfigurator();
                configurator.loadConfig(f);
                LOG.debug("Fediz configuration read from " + f.getAbsolutePath());
            } catch (JAXBException e) {
                LOG.error("Error in parsing configuration", e);
                throw e;
            } catch (MalformedURLException e) {
                LOG.error("Error in loading configuration file", e);
                throw e;
            }
        }
    }
    
    protected boolean checkSecurityContext(Message m) {
        HttpHeaders headers = new HttpHeadersImpl(m);
        Map<String, Cookie> cookies = headers.getCookies();
        
        Cookie securityContextCookie = cookies.get(SECURITY_CONTEXT_TOKEN);
        
        ResponseState responseState = getValidResponseState(securityContextCookie, m);
        if (responseState == null) {
            return false;    
        }
        
        Cookie relayStateCookie = cookies.get(SAMLSSOConstants.RELAY_STATE);
        if (relayStateCookie == null) {
            reportError("MISSING_RELAY_COOKIE");
            return false;
        }
        String originalRelayState = responseState.getRelayState();
        if (!originalRelayState.equals(relayStateCookie.getValue())) {
            // perhaps the response state should also be removed
            reportError("INVALID_RELAY_STATE");
            return false;
        }
        
        // Create SecurityContext
        try {
            SamlAssertionWrapper assertionWrapper = 
                new SamlAssertionWrapper(
                    StaxUtils.read(new StringReader(responseState.getAssertion())).getDocumentElement());
            setSecurityContext(responseState, m, assertionWrapper);
        } catch (Exception ex) {
            reportError("INVALID_RESPONSE_STATE");
            return false;
        }
        
        return true;
    }
    
    protected void setSecurityContext(
        ResponseState responseState, Message m, SamlAssertionWrapper assertionWrapper
    ) throws WSSecurityException {
        CXFFedizPrincipal principal = 
            new CXFFedizPrincipal(responseState.getSubject(), responseState.getClaims(), 
                              assertionWrapper.toDOM(DOMUtils.createDocument()));
        
        SecurityTokenThreadLocal.setToken(principal.getLoginToken());
        FedizSecurityContext context = 
            new FedizSecurityContext(principal, responseState.getRoles());
        m.put(SecurityContext.class, context);
    }
    
    protected ResponseState getValidResponseState(Cookie securityContextCookie, 
                                                  Message m) {
        if (securityContextCookie == null) {
            // most likely it means that the user has not been offered
            // a chance to get logged on yet, though it might be that the browser
            // has removed an expired cookie from its cache; warning is too noisy in the
            // former case
            reportTrace("MISSING_RESPONSE_STATE");
            return null;
        }
        String contextKey = securityContextCookie.getValue();
        
        FedizContext fedizConfig = getFedizContext(m);
        SAMLProtocol protocol = (SAMLProtocol)fedizConfig.getProtocol();
        ResponseState responseState = protocol.getStateManager().getResponseState(contextKey);
        
        if (responseState == null) {
            reportError("MISSING_RESPONSE_STATE");
            return null;
        }
        if (isStateExpired(responseState.getCreatedAt(), responseState.getExpiresAt(), fedizConfig)) {
            reportError("EXPIRED_RESPONSE_STATE");
            protocol.getStateManager().removeResponseState(contextKey);
            return null;
        }
        // TODO String webAppContext = getWebAppContext(m);
        if (webAppDomain != null 
            && (responseState.getWebAppDomain() == null 
                || !webAppDomain.equals(responseState.getWebAppDomain()))) {
            // TODO || responseState.getWebAppContext() == null
            // TODO || !webAppContext.equals(responseState.getWebAppContext())) {
            protocol.getStateManager().removeResponseState(contextKey);
            reportError("INVALID_RESPONSE_STATE");
            return null;
        }
        if (responseState.getAssertion() == null) {
            reportError("INVALID_RESPONSE_STATE");
            return null;
        }
        return responseState;
    }
    
    protected String createCookie(String name, 
                                  String value, 
                                  String path,
                                  String domain,
                                  long stateTimeToLive) { 
        
        String contextCookie = name + "=" + value;
        // Setting a specific path restricts the browsers
        // to return a cookie only to the web applications
        // listening on that specific context path
        if (path != null) {
            contextCookie += ";Path=" + path;
        }
        
        // Setting a specific domain further restricts the browsers
        // to return a cookie only to the web applications
        // listening on the specific context path within a particular domain
        if (domain != null) {
            contextCookie += ";Domain=" + domain;
        }
        
        // Keep the cookie across the browser restarts until it actually expires.
        // Note that the Expires property has been deprecated but apparently is 
        // supported better than 'max-age' property by different browsers 
        // (Firefox, IE, etc)
        Date expiresDate = new Date(System.currentTimeMillis() + stateTimeToLive);
        String cookieExpires = HttpUtils.getHttpDateFormat().format(expiresDate);
        contextCookie += ";Expires=" + cookieExpires;
        //TODO: Consider adding an 'HttpOnly' attribute        
        
        return contextCookie;
    }
    
    protected boolean isStateExpired(long stateCreatedAt, long expiresAt, FedizContext fedizConfig) {
        Date currentTime = new Date();
        long stateTimeToLive = ((SAMLProtocol)fedizConfig.getProtocol()).getStateTimeToLive();
        if (currentTime.after(new Date(stateCreatedAt + stateTimeToLive))) {
            return true;
        }
        
        if (expiresAt > 0 && currentTime.after(new Date(expiresAt))) {
            return true;
        }
        
        return false;
    }
    
    protected FedizContext getFedizContext(Message message) {
        String contextName = new UriInfoImpl(message).getRequestUri().getPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        String[] contextPath = contextName.split("/");
        if (contextPath.length > 0) {
            contextName = "/" + contextPath[1];
        }
        return getContextConfiguration(contextName);
    }
    
    protected FedizContext getContextConfiguration(String contextName) {
        if (configurator == null) {
            throw new IllegalStateException("No Fediz configuration available");
        }
        FedizContext config = configurator.getFedizContext(contextName);
        if (config == null) {
            throw new IllegalStateException("No Fediz configuration for context :" + contextName);
        }
        String catalinaBase = System.getProperty("catalina.base");
        if (catalinaBase != null && catalinaBase.length() > 0) {
            config.setRelativePath(catalinaBase);
        }
        return config;
    }
    
    protected void reportError(String code) {
        org.apache.cxf.common.i18n.Message errorMsg = 
            new org.apache.cxf.common.i18n.Message(code, BUNDLE);
        LOG.warn(errorMsg.toString());
    }
    
    protected void reportTrace(String code) {
        if (LOG.isDebugEnabled()) {
            org.apache.cxf.common.i18n.Message errorMsg = 
                new org.apache.cxf.common.i18n.Message(code, BUNDLE);
            LOG.debug(errorMsg.toString());
        }
    }
/*
 * TODO
    private String getWebAppContext(Message m) {
        if (addWebAppContext) {
            if (addEndpointAddressToContext) {
                return new UriInfoImpl(m).getBaseUri().getRawPath();
            } else {
                String httpBasePath = (String)m.get("http.base.path");
                return URI.create(httpBasePath).getRawPath();
            }
        } else {
            return "/";
        }
    }
  */  
    public String getWebAppDomain() {
        return webAppDomain;
    }

    public void setWebAppDomain(String webAppDomain) {
        this.webAppDomain = webAppDomain;
    }
/*
    public void setAddWebAppContext(boolean addWebAppContext) {
        this.addWebAppContext = addWebAppContext;
    }
    */
        
}
