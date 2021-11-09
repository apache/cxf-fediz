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
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBException;

import org.w3c.dom.Element;

import org.apache.cxf.BusFactory;
import org.apache.cxf.common.i18n.BundleUtils;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.util.CookieUtils;
import org.apache.cxf.fediz.cxf.plugin.state.EHCacheSPStateManager;
import org.apache.cxf.fediz.cxf.plugin.state.ResponseState;
import org.apache.cxf.fediz.cxf.plugin.state.SPStateManager;
import org.apache.cxf.jaxrs.impl.HttpHeadersImpl;
import org.apache.cxf.jaxrs.impl.UriInfoImpl;
import org.apache.cxf.jaxrs.utils.ExceptionUtils;
import org.apache.cxf.jaxrs.utils.ResourceUtils;
import org.apache.cxf.message.Message;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@PreMatching
public abstract class AbstractServiceProviderFilter implements ContainerRequestFilter {

    public static final String SECURITY_CONTEXT_TOKEN =
        "org.apache.fediz.SECURITY_TOKEN";
    public static final String SECURITY_CONTEXT_STATE =
        "org.apache.fediz.SECURITY_CONTEXT_STATE";

    protected static final ResourceBundle BUNDLE =
        BundleUtils.getBundle(AbstractServiceProviderFilter.class);
    private static final Logger LOG = LoggerFactory.getLogger(AbstractServiceProviderFilter.class);

    private boolean addWebAppContext = true;
    private boolean addEndpointAddressToContext;

    private FedizConfigurator configurator;
    private String configFile;
    private SPStateManager stateManager;
    private long stateTimeToLive = 120000;
    private String webAppDomain;

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    @PostConstruct
    public synchronized void configure() throws JAXBException, IOException {
        if (configurator == null) {
            String actualConfigFile = configFile;
            if (actualConfigFile == null) {
                actualConfigFile = "fediz_config.xml";
            }
            try {
                File f = new File(actualConfigFile);
                if (!f.exists()) {
                    URL url = ResourceUtils.getResourceURL(actualConfigFile,
                                                        BusFactory.getThreadDefaultBus());
                    if (url == null) {
                        url = new URL(actualConfigFile);
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
            } catch (IOException e) {
                LOG.error("Error in loading configuration file", e);
                throw e;
            }
        }

        if (stateManager == null) {
            stateManager = new EHCacheSPStateManager("fediz-ehcache.xml");
        }
    }

    @PreDestroy
    public synchronized void cleanup() throws IOException {
        if (configurator != null) {
            List<FedizContext> fedContextList = configurator.getFedizContextList();
            if (fedContextList != null) {
                for (FedizContext fedContext : fedContextList) {
                    try {
                        fedContext.close();
                    } catch (IOException ex) {
                        //
                    }
                }
            }
        }

        if (stateManager != null) {
            stateManager.close();
        }
    }

    protected boolean checkSecurityContext(FedizContext fedConfig, Message m, MultivaluedMap<String, String> params) {
        HttpHeaders headers = new HttpHeadersImpl(m);
        Map<String, Cookie> cookies = headers.getCookies();

        Cookie securityContextCookie = cookies.get(SECURITY_CONTEXT_TOKEN);

        ResponseState responseState = getValidResponseState(securityContextCookie, fedConfig, m);
        if (responseState == null) {
            return false;
        }

        Cookie relayStateCookie = cookies.get(SECURITY_CONTEXT_STATE);
        if (fedConfig.isRequestStateValidation()) {
            if (relayStateCookie == null) {
                reportError("MISSING_RELAY_COOKIE");
                return false;
            }
            String originalRelayState = responseState.getState();
            if (!originalRelayState.equals(relayStateCookie.getValue())) {
                // perhaps the response state should also be removed
                reportError("INVALID_RELAY_STATE");
                return false;
            }

            // Check to see if a CSRF-style attack is being mounted
            String state = getState(fedConfig, params);
            if (state != null && !state.equals(responseState.getState())) {
                LOG.error("wctx parameter does not match stored value");
                throw ExceptionUtils.toForbiddenException(null, null);
            }
        }

        // Create SecurityContext
        try {
            Element token =
                StaxUtils.read(new StringReader(responseState.getAssertion())).getDocumentElement();
            setSecurityContext(responseState, m, token);
        } catch (Exception ex) {
            reportError("INVALID_RESPONSE_STATE");
            return false;
        }

        return true;
    }

    protected void setSecurityContext(
        ResponseState responseState, Message m, Element token
    ) throws WSSecurityException {
        CXFFedizPrincipal principal =
            new CXFFedizPrincipal(responseState.getSubject(), responseState.getClaims(),
                                  responseState.getRoles(), token);

        SecurityTokenThreadLocal.setToken(principal.getLoginToken());
        FedizSecurityContext context =
            new FedizSecurityContext(principal, responseState.getRoles());
        m.put(SecurityContext.class, context);
    }

    protected ResponseState getValidResponseState(Cookie securityContextCookie,
                                                  FedizContext fedConfig,
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
        ResponseState responseState = stateManager.getResponseState(contextKey);

        if (responseState == null) {
            reportError("MISSING_RESPONSE_STATE");
            return null;
        }

        if (CookieUtils.isStateExpired(responseState.getCreatedAt(), fedConfig.isDetectExpiredTokens(),
                                       responseState.getExpiresAt(), getStateTimeToLive())) {
            reportError("EXPIRED_RESPONSE_STATE");
            stateManager.removeResponseState(contextKey);
            return null;
        }

        String webAppContext = getWebAppContext(m);
        if (webAppDomain != null
            && (responseState.getWebAppDomain() == null
                || !webAppDomain.equals(responseState.getWebAppDomain()))
                || responseState.getWebAppContext() == null
                || !webAppContext.equals(responseState.getWebAppContext())) {
            stateManager.removeResponseState(contextKey);
            reportError("INVALID_RESPONSE_STATE");
            return null;
        }
        if (responseState.getAssertion() == null) {
            reportError("INVALID_RESPONSE_STATE");
            return null;
        }
        return responseState;
    }

    protected String getState(FedizContext fedConfig, MultivaluedMap<String, String> params) {
        if (params != null && fedConfig.getProtocol() instanceof FederationProtocol) {
            return params.getFirst(FederationConstants.PARAM_CONTEXT);
        } else if (params != null && fedConfig.getProtocol() instanceof SAMLProtocol) {
            return params.getFirst(SAMLSSOConstants.RELAY_STATE);
        }

        return null;
    }

    protected FedizContext getFedizContext(Message message) {
        String contextName = getWebAppContext(message);
        String[] contextPath = contextName.split("/");
        if (contextPath.length > 0) {
            contextName = "/" + contextPath[1];
        }
        return getContextConfiguration(contextName);
    }

    protected synchronized FedizContext getContextConfiguration(String contextName) {
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

    protected String getWebAppContext(Message m) {
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

    public void setAddWebAppContext(boolean addWebAppContext) {
        this.addWebAppContext = addWebAppContext;
    }

    public SPStateManager getStateManager() {
        return stateManager;
    }

    public void setStateManager(SPStateManager stateManager) {
        this.stateManager = stateManager;
    }

    public String getWebAppDomain() {
        return webAppDomain;
    }

    public void setWebAppDomain(String webAppDomain) {
        this.webAppDomain = webAppDomain;
    }

    public long getStateTimeToLive() {
        return stateTimeToLive;
    }

    public void setStateTimeToLive(long stateTimeToLive) {
        this.stateTimeToLive = stateTimeToLive;
    }
}
