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

package org.apache.cxf.fediz.tomcat7;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;

import org.w3c.dom.Element;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.handler.LogoutHandler;
import org.apache.cxf.fediz.core.metadata.MetadataDocumentHandler;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.apache.cxf.fediz.tomcat7.handler.TomcatLogoutHandler;
import org.apache.cxf.fediz.tomcat7.handler.TomcatSigninHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FederationAuthenticator extends FormAuthenticator {

    public static final String SESSION_SAVED_REQUEST_PREFIX = "SAVED_REQUEST_";
    public static final String SESSION_SAVED_URI_PREFIX = "SAVED_URI_";
    public static final String FEDERATION_NOTE = "org.apache.cxf.fediz.tomcat.FEDERATION";
    public static final String REQUEST_STATE = "org.apache.cxf.fediz.REQUEST_STATE";
    public static final String SECURITY_TOKEN = "org.apache.fediz.SECURITY_TOKEN";

    /**
     * Descriptive information about this implementation.
     */
    protected static final String INFO = "org.apache.cxf.fediz.tomcat.WsFedAuthenticator/1.0";
    protected static final String TRUSTED_ISSUER = "org.apache.cxf.fediz.tomcat.TRUSTED_ISSUER";

    private static final Logger LOG = LoggerFactory.getLogger(FormAuthenticator.class);

    /**
     * Fediz Configuration file
     */
    protected String configFile;
    protected String encoding = "UTF-8";

    private FedizConfigurator configurator;

    public FederationAuthenticator() {
        LOG.debug("WsFedAuthenticator()");
    }

    /**
     * Return descriptive information about this Valve implementation.
     */
    @Override
    public String getInfo() {
        return INFO;
    }

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    @Override
    protected synchronized void startInternal() throws LifecycleException {

        try {
            File f = new File(getConfigFile());
            if (!f.exists()) {
                String catalinaBase = System.getProperty("catalina.base");
                if (catalinaBase != null && catalinaBase.length() > 0) {
                    f = new File(catalinaBase.concat(File.separator + getConfigFile()));
                }
            }
            configurator = new FedizConfigurator();
            configurator.loadConfig(f);
            LOG.debug("Fediz configuration read from " + f.getAbsolutePath());
        } catch (JAXBException | FileNotFoundException e) {
            throw new LifecycleException("Failed to load Fediz configuration", e);
        }
        super.startInternal();

    }

    @Override
    protected synchronized void stopInternal() throws LifecycleException {
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
        super.stopInternal();
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

    @Override
    public void invoke(final Request request, final Response response) throws IOException, ServletException {

        LOG.debug("WsFedAuthenticator:invoke()");
        request.setCharacterEncoding(this.encoding);

        String contextName = request.getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        FedizContext fedConfig = getContextConfiguration(contextName);

        MetadataDocumentHandler mdHandler = new MetadataDocumentHandler(fedConfig);
        if (mdHandler.canHandleRequest(request)) {
            mdHandler.handleRequest(request, response);
            return;
        }

        LogoutHandler logoutHandler = new TomcatLogoutHandler(fedConfig, contextName, request);
        if (logoutHandler.canHandleRequest(request)) {
            Element token = (Element)request.getSession().getAttribute(SECURITY_TOKEN);
            logoutHandler.setToken(token);
            logoutHandler.handleRequest(request, response);
            return;
        }

        super.invoke(request, response);
    }

    @Override
    public boolean authenticate(Request request, HttpServletResponse response,
            LoginConfig config) throws IOException {
        
        LOG.debug("authenticate invoked");
        
        String contextName = request.getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        LOG.debug("reading configuration for context path: {}", contextName);
        FedizContext fedCtx = getContextConfiguration(contextName);
        
        // Handle Signin requests
        TomcatSigninHandler signinHandler = new TomcatSigninHandler(fedCtx);
        signinHandler.setLandingPage(landingPage);
        if (signinHandler.canHandleRequest(request)) {
            FedizPrincipal principal = signinHandler.handleRequest(request, response);
            if (principal != null) {
                LOG.debug("Authentication of '{}' was successful", principal);
                resumeRequest(request, response);
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
            // The actual login will take place after redirect
            return false;
        }
        
        // Is this the re-submit of the original request URI after successful
        // authentication? If so, forward the *original* request instead.
        if (matchRequest(request)) {
            return restoreRequest(request, response);
        }

        // Check if user was authenticated previously and token is still valid
        if (checkUserAuthentication(request, response, fedCtx)) {
            return true;
        }

        LOG.info("No valid principal found in existing session. Redirecting to IDP");
        redirectToIdp(request, response, fedCtx);
        return false;
    }

    protected void resumeRequest(HttpServletRequest request, HttpServletResponse response) {
        String originalURL = null;
        String contextId = request.getParameter(FederationConstants.PARAM_CONTEXT);
        if (contextId != null) {
            Session session = ((Request)request).getSessionInternal();
            originalURL = (String)session.getNote(FederationAuthenticator.SESSION_SAVED_URI_PREFIX + contextId);
            session.removeNote(FederationAuthenticator.SESSION_SAVED_URI_PREFIX + contextId); // Cleanup session
            
        } else {
            LOG.warn("The 'wctx' parameter has not been provided back with signin request. "
                + "Trying to resume now with signin URL (without parameters)");
            originalURL = request.getRequestURI();
        }
        try {
            if (originalURL != null) {
                LOG.debug("Restore request to {}", originalURL);
                response.sendRedirect(response.encodeRedirectURL(originalURL));
            } else {
                LOG.debug("User took so long to log on the session expired");
                if (landingPage == null) {
                    response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT, sm
                        .getString("authenticator.sessionExpired"));
                } else {
                    // Redirect to landing page
                    String uri = request.getContextPath() + landingPage;
                    response.sendRedirect(response.encodeRedirectURL(uri));
                }
            }
        } catch (IOException e) {
            LOG.error("Cannot resume with request.", e.getMessage());
        }
    }
    
    protected boolean restoreRequest(Request request, HttpServletResponse response) throws IOException {

        Session session = request.getSessionInternal();
        LOG.debug("Restore request from session '{}'", session.getIdInternal());

        // Get principal from session, register, and then remove it
        Principal principal = (Principal)session.getNote(Constants.FORM_PRINCIPAL_NOTE);
        register(request, response, principal, FederationConstants.WSFED_METHOD, null, null);
        request.removeNote(Constants.FORM_PRINCIPAL_NOTE);

        if (restoreRequest(request)) {
            LOG.debug("Proceed to restored request");
            return true;
        } else {
            LOG.warn("Restore of original request failed");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return false;
        }
    }

    protected void redirectToIdp(Request request, HttpServletResponse response, FedizContext fedCtx) 
        throws IOException {

        FedizProcessor processor = FedizProcessorFactory.newFedizProcessor(fedCtx.getProtocol());
        try {
            RedirectionResponse redirectionResponse = processor.createSignInRequest(request, fedCtx);
            String redirectURL = redirectionResponse.getRedirectionURL();
            if (redirectURL != null) {
                Map<String, String> headers = redirectionResponse.getHeaders();
                if (!headers.isEmpty()) {
                    for (String headerName : headers.keySet()) {
                        response.addHeader(headerName, headers.get(headerName));
                    }
                }

                // Save original request in our session
                try {
                    saveRequest(request, redirectionResponse.getRequestState().getState());
                } catch (IOException ioe) {
                    LOG.debug("Request body too big to save during authentication");
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, sm
                        .getString("authenticator.requestBodyTooBig"));
                }

                response.sendRedirect(redirectURL);
            } else {
                LOG.warn("Failed to create SignInRequest.");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
            }
        } catch (ProcessingException ex) {
            LOG.warn("Failed to create SignInRequest: {}", ex.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
        }
    }
    
    @Override
    protected boolean matchRequest(Request request) {
        Session session = request.getSessionInternal(false);
        String uri = request.getDecodedRequestURI();
        if (session != null && uri != null) {
            SavedRequest saved = (SavedRequest) session.getNote(SESSION_SAVED_REQUEST_PREFIX + uri);
            if (saved != null) {
                synchronized (session) {
                    session.setNote(Constants.FORM_REQUEST_NOTE, saved);
                    return super.matchRequest(request);
                }
            }
        } 
        return false;
    }
    
    protected void saveRequest(Request request, String contextId) throws IOException {
        String uri = request.getDecodedRequestURI();
        Session session = request.getSessionInternal(true);
        LOG.debug("Save request in session '{}'", session.getIdInternal());
        if (session != null && uri != null) {
            SavedRequest saved;
            synchronized (session) {
                super.saveRequest(request, session);
                saved = (SavedRequest) session.getNote(Constants.FORM_REQUEST_NOTE);
            }
            session.setNote(SESSION_SAVED_REQUEST_PREFIX + uri, saved);
            StringBuilder sb = new StringBuilder(saved.getRequestURI());
            if (saved.getQueryString() != null) {
                sb.append('?');
                sb.append(saved.getQueryString());
            }
            session.setNote(SESSION_SAVED_URI_PREFIX + contextId, sb.toString());
        }
    }
    
    protected boolean restoreRequest(Request request) throws IOException {
        Session session = request.getSessionInternal(false);
        String uri = request.getDecodedRequestURI();
        if (session != null && uri != null) {
            SavedRequest saved = (SavedRequest)session.getNote(SESSION_SAVED_REQUEST_PREFIX + uri);
            if (saved != null) {
                session.removeNote(SESSION_SAVED_REQUEST_PREFIX + uri); // cleanup session
                synchronized (session) {
                    session.setNote(Constants.FORM_REQUEST_NOTE, saved);
                    return super.restoreRequest(request, session);
                }
            }
        }
        return false;
    }

    protected boolean checkUserAuthentication(Request request, HttpServletResponse response, FedizContext fedCtx) {
        // Have we already authenticated someone?
        Principal principal = request.getUserPrincipal();
        // String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
        if (principal != null) {
            LOG.debug("Already authenticated '{}'", principal.getName());

            // Associate the session with any existing SSO session
            /*
             * if (ssoId != null) associate(ssoId, request.getSessionInternal(true));
             */

            if (fedCtx.isDetectExpiredTokens()) {
                // Check whether security token still valid
                return validateToken(request, response, fedCtx);
            } else {
                LOG.debug("Token expiration not validated.");
                return true;
            }
        }
        return false;
    }

    protected boolean validateToken(Request request, HttpServletResponse response, FedizContext fedConfig) {
        Session session = request.getSessionInternal();
        if (session != null) {

            FedizResponse wfRes = (FedizResponse)session.getNote(FEDERATION_NOTE);
            Date tokenExpires = wfRes.getTokenExpires();
            if (tokenExpires == null) {
                LOG.debug("Token doesn't expire");
                return true;
            }

            Date currentTime = new Date();
            if (!currentTime.after(tokenExpires)) {
                return true;
            } else {
                LOG.warn("Token already expired. Clean up and redirect");

                session.removeNote(FEDERATION_NOTE);
                session.setPrincipal(null);
                request.getSession().removeAttribute(SECURITY_TOKEN);
            }
        } else {
            LOG.debug("Session should not be null after authentication");
        }
        return false;
    }

    @Override
    protected String getAuthMethod() {
        return FederationConstants.WSFED_METHOD;
    }

}
