/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.cxf.fediz.tomcat;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.FederationProcessor;
import org.apache.cxf.fediz.core.FederationProcessorImpl;
import org.apache.cxf.fediz.core.FederationRequest;
import org.apache.cxf.fediz.core.FederationResponse;
import org.apache.cxf.fediz.core.config.FederationConfigurator;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class FederationAuthenticator extends FormAuthenticator {

    // [TODO] Expired token

    private static final Log log = LogFactory.getLog(FormAuthenticator.class);

    /**
     * Descriptive information about this implementation.
     */
    protected static final String info = "org.apache.cxf.fediz.tomcat.WsFedAuthenticator/1.0";

    public static final String FEDERATION_NOTE = "org.apache.cxf.fediz.tomcat.FEDERATION";

    public static final String SECURITY_TOKEN = "org.apache.fediz.SECURITY_TOKEN";

    protected static final String TRUSTED_ISSUER = "org.apache.cxf.fediz.tomcat.TRUSTED_ISSUER";


    /**
     * Fediz Configuration file
     */
    protected String configFile = null;

    private FederationConfigurator configurator = null;

    public FederationAuthenticator() {
        log.debug("WsFedAuthenticator()");
    }

    /**
     * Return descriptive information about this Valve implementation.
     */
    @Override
    public String getInfo() {
        return (info);
    }

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    @Override
    protected synchronized void startInternal() throws LifecycleException {

        try {
            File f = new File(getConfigFile());
            if (!f.exists()) {
                String catalinaHome = System.getProperty("catalina.home");
                if (catalinaHome != null && catalinaHome.length() > 0) {
                    f = new File(catalinaHome.concat(File.separator + getConfigFile()));
                }
            }
            configurator = new FederationConfigurator();
            configurator.loadConfig(f);
            log.debug("Fediz configuration read from " + f.getAbsolutePath());
        } catch (JAXBException e) {
            throw new LifecycleException("Failed to load Fediz configuration",
                    e);
        }
        super.startInternal();

    }

    private FederationContext getContextConfiguration(String contextName) {
        if (configurator == null) {
            throw new IllegalStateException("No Fediz configuration available");
        }
        FederationContext config = configurator.getFederationContext(contextName);
        if (config == null) {
            throw new IllegalStateException("No Fediz configuration for context :" + contextName);
        }
        String catalinaHome = System.getProperty("catalina.home");
        if (catalinaHome != null && catalinaHome.length() > 0) {
            config.setRelativePath(catalinaHome);
        }
        return config;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException,
    ServletException {

        log.debug("WsFedAuthenticator:invoke()");
        super.invoke(request, response);

    }

    @Override
    public boolean authenticate(Request request, HttpServletResponse response,
            LoginConfig config) throws IOException {

        log.debug("authenticate invoked");
        // References to objects we will need later
        Session session = null;

        // Have we already authenticated someone?
        Principal principal = request.getUserPrincipal();
        // String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
        if (principal != null) {
            if (log.isDebugEnabled())
                log.debug("Already authenticated '" + principal.getName() + "'");
            // Associate the session with any existing SSO session
            /*
             * if (ssoId != null) associate(ssoId,
             * request.getSessionInternal(true));
             */

            // Check whether security token still valid
            session = request.getSessionInternal();
            if (session == null) {
                log.debug("Session should not be null after authentication");
            } else {
                FederationResponse wfRes = (FederationResponse) session
                .getNote(FEDERATION_NOTE);

                Date tokenExpires = wfRes.getTokenExpires();
                if (tokenExpires == null) {
                    log.debug("Token doesn't expire");
                    return (true);
                }
                Calendar cal = Calendar.getInstance();
                if (cal.getTime().after(wfRes.getTokenExpires())) {
                    log.debug("Token already expired. Clean up and redirect");

                    session.removeNote(FEDERATION_NOTE);
                    session.removeNote(Constants.FORM_PRINCIPAL_NOTE);
                    session.setPrincipal(null);
                    request.getSession().removeAttribute(SECURITY_TOKEN);

                    if (log.isDebugEnabled())
                        log.debug("Save request in session '"
                                + session.getIdInternal() + "'");
                    try {
                        saveRequest(request, session);
                    } catch (IOException ioe) {
                        log.debug("Request body too big to save during authentication");
                        response.sendError(HttpServletResponse.SC_FORBIDDEN,
                                sm.getString("authenticator.requestBodyTooBig"));
                        return (false);
                    }
                    FederationProcessor wfProc = new FederationProcessorImpl();
                    redirectToIssuer(request, response, wfProc);

                    return (false);
                }
            }

            return (true);
        }

        // Is this the re-submit of the original request URI after successful
        // authentication? If so, forward the *original* request instead.
        if (matchRequest(request)) {
            session = request.getSessionInternal(true);
            if (log.isDebugEnabled())
                log.debug("Restore request from session '"
                        + session.getIdInternal() + "'");
            principal = (Principal) session
            .getNote(Constants.FORM_PRINCIPAL_NOTE);
            register(request, response, principal,
                    FederationConstants.WSFED_METHOD, null, null);

            if (restoreRequest(request, session)) {
                if (log.isDebugEnabled())
                    log.debug("Proceed to restored request");
                return (true);
            } else {
                if (log.isDebugEnabled())
                    log.debug("Restore of original request failed");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return (false);
            }
        }

        // Acquire references to objects we will need to evaluate
        /*
         * MessageBytes uriMB = MessageBytes.newInstance(); CharChunk uriCC =
         * uriMB.getCharChunk(); uriCC.setLimit(-1);
         */
        // String contextPath = request.getContextPath();
        String requestURI = request.getDecodedRequestURI();

        String wa = request.getParameter("wa");
        // Unauthenticated -> redirect
        if (wa == null) {
            session = request.getSessionInternal(true);
            if (log.isDebugEnabled())
                log.debug("Save request in session '" + session.getIdInternal()
                        + "'");
            try {
                saveRequest(request, session);
            } catch (IOException ioe) {
                log.debug("Request body too big to save during authentication");
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        sm.getString("authenticator.requestBodyTooBig"));
                return (false);
            }
            FederationProcessor wfProc = new FederationProcessorImpl();
            redirectToIssuer(request, response, wfProc);
            return (false);
        }

        // Check whether it is the signin request, validate the token.
        // If failed, redirect to the error page if they are not correct
        String wresult = request.getParameter("wresult");
        FederationResponse wfRes = null;
        if (wa.equals(FederationConstants.ACTION_SIGNIN)) {
            if (log.isDebugEnabled()) {
                log.debug("SignIn request found");
                log.debug("SignIn action...");
            }

            if (wresult == null) {
                if (log.isDebugEnabled())
                    log.debug("SignIn request must contain wresult");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return (false);
            } else {
                request.getResponse().sendAcknowledgement();
                // processSignInRequest
                if (log.isDebugEnabled()) {
                    log.debug("Process SignIn request");
                    log.debug("wresult=\n" + wresult);
                }

                FederationRequest wfReq = new FederationRequest();
                wfReq.setWa(wa);
                wfReq.setWresult(wresult);

                String contextName = request.getServletContext().getContextPath();
                if (contextName == null || contextName.isEmpty()) {
                    contextName = "/";
                }
                FederationContext fedConfig = getContextConfiguration(contextName);

                // Has the callback handler returned a trusted issuer, stored in
                // session
//                session = request.getSessionInternal();
//                String trustedIssuer = null;
//
//                //[TODO] How to cache trusted issuer from FederationProcessor?
//                if (session != null) {
//                    trustedIssuer = (String) session.getNote(TRUSTED_ISSUER);
//                    if (trustedIssuer == null || trustedIssuer.length() == 0) {
//                        trustedIssuer = ((FederationProtocolType)fedConfig.getProtocol()).getIssuer();
//                    } else {
//                        log.debug("Trusted issuer cached in session");
//                        session.removeNote(TRUSTED_ISSUER);
//                    }
//                } else {
//                    log.debug("request session null");
//                }

                // fedConfig.setTrustedIssuer(trustedIssuer);
                // log.info("Trusted issuer: " + trustedIssuer);
                //

                FederationProcessor wfProc = new FederationProcessorImpl();
                wfRes = wfProc.processRequest(wfReq, fedConfig);
                
                // Validate the AudienceRestriction in Security Token (e.g. SAML) 
                // against the configured list of audienceURIs
                if (wfRes.getAudience() != null) {
                    List<String> audienceURIs = fedConfig.getAudienceUris();
                    boolean validAudience = false;
                    for (String a : audienceURIs) {
                        if (wfRes.getAudience().startsWith(a)) {
                            validAudience = true;
                            break;
                        }
                    }
                    
                    if (!validAudience) {
                        log.warn("Token AudienceRestriction [" + wfRes.getAudience() + "] doesn't match with specified list of URIs.");
                            response.sendError(HttpServletResponse.SC_FORBIDDEN);
                            return (false);
                    }
                    
                    if (log.isDebugEnabled() && request.getRequestURL().indexOf(wfRes.getAudience()) == -1) {
                        log.debug("Token AudienceRestriction doesn't match with request URL ["
                                + wfRes.getAudience() + "]  ["
                                + request.getRequestURL() + "]");
                    }
                }

                List<String> roles = wfRes.getRoles();
                if (roles == null || roles.size() == 0) {
                    roles = new ArrayList<String>();
                    roles.add(new String("Authenticated"));
                }

                principal = new FederationPrincipalImpl(wfRes.getUsername(), roles,
                        wfRes.getClaims());

                // [TODO] Cache lifetime (in session), token (in session/TLS),
                // ?audience?
                // [TODO] clocksqew
            }
        } else {
            log.error("Not supported action found in parameter wa: " + wa);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return (false);
        }

        /*
         * Realm realm = context.getRealm(); if (characterEncoding != null) {
         * request.setCharacterEncoding(characterEncoding);
         * 
         * String username = request.getParameter(Constants.FORM_USERNAME);
         * String password = request.getParameter(Constants.FORM_PASSWORD); if
         * (log.isDebugEnabled()) log.debug("Authenticating username '" +
         * username + "'"); principal = realm.authenticate(username, password);
         */
        if (principal == null) {
            forwardToErrorPage(request, response, config);
            return (false);
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication of '" + principal + "' was successful");
        }
        // context.addServletContainerInitializer(sci, classes)
        // session.addSessionListener(listener)
        // HttpSessionAttributeListener

        if (session == null)
            session = request.getSessionInternal(false);
        if (session == null) {
            if (containerLog.isDebugEnabled())
                containerLog
                .debug("User took so long to log on the session expired");
            if (landingPage == null) {
                response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT,
                        sm.getString("authenticator.sessionExpired"));
            } else {
                // Make the authenticator think the user originally requested
                // the landing page
                String uri = request.getContextPath() + landingPage;
                SavedRequest saved = new SavedRequest();
                saved.setMethod("GET");
                saved.setRequestURI(uri);
                request.getSessionInternal(true).setNote(
                        Constants.FORM_REQUEST_NOTE, saved);
                response.sendRedirect(response.encodeRedirectURL(uri));
            }
            return (false);
        }

        // Save the authenticated Principal in our session
        session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

        // Save Federation response in our session
        session.setNote(FEDERATION_NOTE, wfRes);

        // Save Federation response in public session
        request.getSession(true).setAttribute(SECURITY_TOKEN, wfRes.getToken());

        /*
         * // Save the username and password as well
         * session.setNote(Constants.SESS_USERNAME_NOTE, username);
         * session.setNote(Constants.SESS_PASSWORD_NOTE, password);
         */
        // Redirect the user to the original request URI (which will cause
        // the original request to be restored)
        requestURI = savedRequestURL(session);
        if (log.isDebugEnabled())
            log.debug("Redirecting to original '" + requestURI + "'");
        if (requestURI == null)
            if (landingPage == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        sm.getString("authenticator.formlogin"));
            } else {
                // Make the authenticator think the user originally requested
                // the landing page
                String uri = request.getContextPath() + landingPage;
                SavedRequest saved = new SavedRequest();
                saved.setMethod("GET");
                saved.setRequestURI(uri);
                session.setNote(Constants.FORM_REQUEST_NOTE, saved);

                response.sendRedirect(response.encodeRedirectURL(uri));
            }
        else
            response.sendRedirect(response.encodeRedirectURL(requestURI));
        return (false);
    }

    @Override
    protected String getAuthMethod() {
        return FederationConstants.WSFED_METHOD;
    }

    /**
     * Called to redirect to the IDP/Issuer
     * 
     * @param request
     *            Request we are processing
     * @param response
     *            Response we are populating
     * @param processor
     *            FederationProcessor
     * @throws IOException
     *             If the forward to the login page fails and the call to
     *             {@link HttpServletResponse#sendError(int, String)} throws an
     *             {@link IOException}
     */
    protected void redirectToIssuer(Request request,
            HttpServletResponse response, FederationProcessor processor)
    throws IOException {

        String contextName = request.getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        FederationContext fedCtx = this.configurator.getFederationContext(contextName);
        String redirectURL = processor.createSignInRequest(request, fedCtx);
        if (redirectURL == null) {
            log.warn("Failed to create SignInRequest.");
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
        } else {
            response.sendRedirect(redirectURL);
        }
    }

}
