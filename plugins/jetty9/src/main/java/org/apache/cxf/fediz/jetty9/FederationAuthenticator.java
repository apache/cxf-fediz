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

package org.apache.cxf.fediz.jetty9;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBException;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.metadata.MetadataDocumentHandler;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Authentication.User;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.MultiMap;
import org.eclipse.jetty.util.URIUtil;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

/**
 * Federation Authenticator.
 * <p>
 * This authenticator implements form authentication will redirect to the Identity Provider
 * by sending a WS-Federation SignIn request.
 * </p>
 * <p>
 * The federation authenticator redirects unauthenticated requests to an Identity Provider which use any kind of 
 * mechanism to authenticate the user.
 * FederationAuthentication uses {@link SessionAuthentication} to wrap Authentication results so that they are
 * associated with the session.
 * </p>
 */
// CHECKSTYLE:OFF
public class FederationAuthenticator extends LoginAuthenticator {
    
    public static final String J_URI = "org.eclipse.jetty.security.form_URI";
    public static final String J_POST = "org.eclipse.jetty.security.form_POST";

    private static final Logger LOG = Log.getLogger(FederationAuthenticator.class);
    
    private static final String SECURITY_TOKEN_ATTR = "org.apache.fediz.SECURITY_TOKEN";
       
    private String configFile;
    private FedizConfigurator configurator;
    private String encoding = "UTF-8";

    public FederationAuthenticator() {
    }


    /**
     * 
     */
    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        super.setConfiguration(configuration);
        // is called after the bean setting -> do initialization here
        LOG.debug(configuration.getInitParameterNames().toString());
        try {
            File f = new File(getConfigFile());
            if (!f.exists()) {
                String jettyHome = System.getProperty("jetty.home");
                if (jettyHome != null && jettyHome.length() > 0) {
                    f = new File(jettyHome.concat(File.separator + getConfigFile()));
                }
            }
            configurator = new FedizConfigurator();
            configurator.loadConfig(f);
            LOG.debug("Fediz configuration read from " + f.getAbsolutePath());
        } catch (JAXBException | FileNotFoundException e) {
            //[TODO] use other exception
            throw new RuntimeException("Failed to load Fediz configuration",
                    e);
            //throw new ServerAuthException("Failed to load Fediz configuration",
            //                              e);
        }
        
    }

    /* ------------------------------------------------------------ */
    public String getAuthMethod() {
        return "WSFED";
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
    
    /* ------------------------------------------------------------ */
    public Authentication validateRequest(ServletRequest req, ServletResponse res, boolean mandatory)
        throws ServerAuthException {
        
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;

        HttpSession session = request.getSession(true);
        
        String contextName = request.getSession().getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        FedizContext fedConfig = getContextConfiguration(contextName);
        
        // Check to see if it is a metadata request
        MetadataDocumentHandler mdHandler = new MetadataDocumentHandler(fedConfig);
        if (mdHandler.canHandleRequest(request)) {
            if (mdHandler.handleRequest(request, response)) {
                return Authentication.SEND_CONTINUE;
            }
            return Authentication.SEND_FAILURE;
        }

        if (!mandatory) {
            return new DeferredAuthentication(this);
        }
        
        try {
            req.setCharacterEncoding(this.encoding);
        } catch (UnsupportedEncodingException ex) {
            LOG.warn("Unsupported encoding '" + this.encoding + "'", ex);
        }
        
        String uri = request.getRequestURI();
        if (uri == null) {
            uri = URIUtil.SLASH;
        }

        try {
            String action = request.getParameter(FederationConstants.PARAM_ACTION);
            String responseToken = getResponseToken(request, fedConfig);
            
            // Handle a request for authentication.
            if (isSignInRequest(request, fedConfig)) {

                FedizResponse wfRes = null;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SignIn request found");
                }

                if (responseToken == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("SignIn request must contain a response token from the IdP");
                    }
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                    return Authentication.SEND_FAILURE;
                } else {

                    FedizRequest wfReq = new FedizRequest();
                    wfReq.setAction(action);
                    wfReq.setResponseToken(responseToken);
                    wfReq.setState(request.getParameter("RelayState"));
                    wfReq.setRequest(request);

                    X509Certificate certs[] = 
                        (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
                    wfReq.setCerts(certs);

                    FederationLoginService fedLoginService = (FederationLoginService)this._loginService;
                    UserIdentity user = fedLoginService.login(null, wfReq, fedConfig);
                    if (user != null)
                    {
                        session=renewSession(request,response);

                        FederationUserIdentity fui = (FederationUserIdentity)user;
                        session.setAttribute(SECURITY_TOKEN_ATTR, fui.getToken());

                        // Redirect to original request
                        String nuri;
                        synchronized(session)
                        {
                            nuri = (String) session.getAttribute(J_URI);

                            if (nuri == null || nuri.length() == 0)
                            {
                                nuri = request.getContextPath();
                                if (nuri.length() == 0) { 
                                    nuri = URIUtil.SLASH;
                                }
                            }
                            Authentication cached=new SessionAuthentication(getAuthMethod(), user, wfRes);
                            session.setAttribute(SessionAuthentication.__J_AUTHENTICATED, cached);
                        }
                        response.setContentLength(0);   
                        response.sendRedirect(response.encodeRedirectURL(nuri));

                        return new FederationAuthentication(getAuthMethod(), user);
                    }

                    // not authenticated
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("WSFED authentication FAILED");
                    }
                    if (response != null) {
                        response.sendError(HttpServletResponse.SC_FORBIDDEN);
                    }

                }
            } else if (FederationConstants.ACTION_SIGNOUT_CLEANUP.equals(action)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SignOutCleanup request found");
                    LOG.debug("SignOutCleanup action...");
                }
                session.invalidate();

                final ServletOutputStream responseOutputStream = response.getOutputStream();
                InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("logout.jpg");
                if (inputStream == null) {
                    LOG.warn("Could not write logout.jpg");
                    return Authentication.SEND_FAILURE;
                }
                int read = 0;
                byte[] buf = new byte[1024];
                while ((read = inputStream.read(buf)) != -1) {
                    responseOutputStream.write(buf, 0, read);
                }
                inputStream.close();
                responseOutputStream.flush();
                return Authentication.SEND_SUCCESS;
            } else if (action != null) {
                LOG.warn("Not supported action found in parameter wa: " + action);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return Authentication.UNAUTHENTICATED;
            }

            // Look for cached authentication
            Authentication authentication = (Authentication) session.getAttribute(SessionAuthentication.__J_AUTHENTICATED);
            if (authentication != null) 
            {
                // Has authentication been revoked?
                if (authentication instanceof Authentication.User
                    && isTokenExpired(fedConfig, ((Authentication.User)authentication).getUserIdentity())) {
                    session.removeAttribute(SessionAuthentication.__J_AUTHENTICATED);
                }
                else
                {
                    //logout
                    String logoutUrl = fedConfig.getLogoutURL();
                    if (logoutUrl != null && !logoutUrl.isEmpty() && uri.equals(contextName + logoutUrl)) {
                        session.invalidate();

                        FedizProcessor wfProc = 
                            FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());
                        signOutRedirectToIssuer(request, response, wfProc);

                        return Authentication.SEND_CONTINUE;
                    }

                    String j_uri = (String)session.getAttribute(J_URI);
                    if (j_uri != null)
                    {
                        @SuppressWarnings("unchecked")
                        MultiMap<String> j_post = (MultiMap<String>)session.getAttribute(J_POST);
                        if (j_post != null)
                        {
                            StringBuffer buf = request.getRequestURL();
                            if (request.getQueryString() != null) {
                                buf.append("?").append(request.getQueryString());
                            }

                            if (j_uri.equals(buf.toString()))
                            {
                                // This is a retry of an original POST request
                                // so restore method and parameters

                                session.removeAttribute(J_POST);            
                                Request base_request = (Request)req; 
                                    // (req instanceof Request)?(Request)req:HttpConnection.getCurrentConnection().getRequest();
                                base_request.setMethod(HttpMethod.POST.asString());
                                base_request.setQueryParameters(j_post);
                            }
                        }
                        else
                            session.removeAttribute(J_URI);
                            
                    }
                    return authentication;
                }
            }          
            

            // if we can't send challenge
            if (DeferredAuthentication.isDeferred(response))
            {
                LOG.debug("auth deferred {}",session.getId());
                return Authentication.UNAUTHENTICATED;
            }
            
            // remember the current URI
            synchronized (session)
            {
                // But only if it is not set already, or we save every uri that leads to a login form redirect
                if (session.getAttribute(J_URI)==null) // || alwaysSaveUri)
                {  
                    StringBuffer buf = request.getRequestURL();
                    if (request.getQueryString() != null) {
                        buf.append("?").append(request.getQueryString());
                    }
                    session.setAttribute(J_URI, buf.toString());
                    
                    if (MimeTypes.Type.FORM_ENCODED.equals(req.getContentType()) && HttpMethod.POST.equals(request.getMethod()))
                    {
                        Request base_request = (Request)req; 
                            //(req instanceof Request)?(Request)req:HttpConnection.getCurrentConnection().getRequest();
                        base_request.extractParameters();   
                        session.setAttribute(J_POST, new MultiMap<String>(base_request.getQueryParameters()));
                    }
                }
            }
            
            FedizProcessor wfProc = 
                FedizProcessorFactory.newFedizProcessor(fedConfig.getProtocol());
            signInRedirectToIssuer(request, response, wfProc);

            return Authentication.SEND_CONTINUE;

        } catch (IOException e) {
            throw new ServerAuthException(e);
        }
        /*
         * catch (ServletException e) { throw new ServerAuthException(e); }
         */
    }
    
    private boolean isTokenExpired(FedizContext fedConfig, UserIdentity userIdentity) {
        if (fedConfig.isDetectExpiredTokens()) {
            try {
                FederationUserIdentity fui = (FederationUserIdentity)userIdentity;
                Date tokenExpires = fui.getExpiryDate();
                if (tokenExpires == null) {
                    LOG.debug("Token doesn't expire");
                    return false;
                }
    
                Date currentTime = new Date();
                if (!currentTime.after(tokenExpires)) {
                    return false;
                } else {
                    LOG.warn("Token already expired. Clean up and redirect");
    
                    return true;
                }
            } catch (ClassCastException ex) {
                LOG.warn("UserIdentity must be instance of FederationUserIdentity");
                throw new IllegalStateException("UserIdentity must be instance of FederationUserIdentity");
            }
        }
        
        return false;
    }

    private boolean isSignInRequest(ServletRequest request, FedizContext fedConfig) {
        if (fedConfig.getProtocol() instanceof FederationProtocol
            && FederationConstants.ACTION_SIGNIN.equals(
                request.getParameter(FederationConstants.PARAM_ACTION))) {
            return true;
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol
            && request.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return true;
        }

        return false;
    }
    
    private String getResponseToken(ServletRequest request, FedizContext fedConfig) {
        if (fedConfig.getProtocol() instanceof FederationProtocol) {
            return request.getParameter(FederationConstants.PARAM_RESULT);
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol) {
            return request.getParameter(SAMLSSOConstants.SAML_RESPONSE);
        }
        return null;
    }
    
    /* ------------------------------------------------------------ */
    public boolean secureResponse(ServletRequest req, ServletResponse res, boolean mandatory,
                                  User validatedUser) throws ServerAuthException {
        return true;
    }    
    
    /**
     * Called to redirect sign-in to the IDP/Issuer
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
    protected void signInRedirectToIssuer(HttpServletRequest request, HttpServletResponse response, FedizProcessor processor)
        throws IOException {

        //Not supported in jetty 7.6
        //String contextName = request.getServletContext().getContextPath();
        String contextName = request.getSession().getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        FedizContext fedCtx = this.configurator.getFedizContext(contextName);
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
                
                response.sendRedirect(redirectURL);
            } else {
                LOG.warn("Failed to create SignInRequest.");
                response.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
            }
        } catch (ProcessingException ex) {
            LOG.warn("Failed to create SignInRequest: " + ex.getMessage());
            response.sendError(
                               HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignInRequest.");
        }
        
    }

    protected void signOutRedirectToIssuer(HttpServletRequest request, HttpServletResponse response, FedizProcessor processor)
            throws IOException {

        //Not supported in jetty 7.6
        //String contextName = request.getServletContext().getContextPath();
        String contextName = request.getSession().getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        FedizContext fedCtx = this.configurator.getFedizContext(contextName);
        try {
            RedirectionResponse redirectionResponse = 
                processor.createSignOutRequest(request, null, fedCtx); //TODO
            String redirectURL = redirectionResponse.getRedirectionURL();
            if (redirectURL != null) {
                Map<String, String> headers = redirectionResponse.getHeaders();
                if (!headers.isEmpty()) {
                    for (String headerName : headers.keySet()) {
                        response.addHeader(headerName, headers.get(headerName));
                    }
                }
                
                response.sendRedirect(redirectURL);
            } else {
                LOG.warn("Failed to create SignOutRequest.");
                response.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignOutRequest.");
            }
        } catch (ProcessingException ex) {
            LOG.warn("Failed to create SignOutRequest: " + ex.getMessage());
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create SignOutRequest.");
        }
    }
    
    private FedizContext getContextConfiguration(String contextName) {
        if (configurator == null) {
            throw new IllegalStateException("No Fediz configuration available");
        }
        FedizContext config = configurator.getFedizContext(contextName);
        if (config == null) {
            throw new IllegalStateException("No Fediz configuration for context :" + contextName);
        }
        
        String jettyHome = System.getProperty("jetty.home");
        if (jettyHome != null && jettyHome.length() > 0) {
            config.setRelativePath(jettyHome);
        }
        return config;
    }

    /* ------------------------------------------------------------ */
    /**
     * This Authentication represents a just completed Federation authentication. Subsequent requests from the same
     * user are authenticated by the presents of a {@link SessionAuthentication} instance in their session.
     */
    public static class FederationAuthentication extends UserAuthentication implements
        Authentication.ResponseSent {
        
        public FederationAuthentication(String method, UserIdentity userIdentity) {
            super(method, userIdentity);
        }

        @Override
        public String toString() {
            return "WSFED" + super.toString();
        }
    }
}
