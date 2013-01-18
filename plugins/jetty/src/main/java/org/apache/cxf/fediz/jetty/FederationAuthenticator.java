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

package org.apache.cxf.fediz.jetty;

import java.io.File;
import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBException;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.FederationProcessor;
import org.apache.cxf.fediz.core.FederationProcessorImpl;
import org.apache.cxf.fediz.core.FederationRequest;
import org.apache.cxf.fediz.core.FederationResponse;
import org.apache.cxf.fediz.core.config.FederationConfigurator;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.eclipse.jetty.http.HttpMethods;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.server.AbstractHttpConnection;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Authentication.User;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.MultiMap;
import org.eclipse.jetty.util.StringUtil;
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
    private FederationConfigurator configurator;

    public FederationAuthenticator() {
    }


    /**
     * 
     */
    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        super.setConfiguration(configuration);
        // is called after the bean setting -> do initialization here
        System.out.println(configuration.getInitParameterNames());
        try {
            File f = new File(getConfigFile());
            if (!f.exists()) {
                String jettyHome = System.getProperty("jetty.home");
                if (jettyHome != null && jettyHome.length() > 0) {
                    f = new File(jettyHome.concat(File.separator + getConfigFile()));
                }
            }
            configurator = new FederationConfigurator();
            configurator.loadConfig(f);
            LOG.debug("Fediz configuration read from " + f.getAbsolutePath());
        } catch (JAXBException e) {
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
    
    /* ------------------------------------------------------------ */
    public Authentication validateRequest(ServletRequest req, ServletResponse res, boolean mandatory)
        throws ServerAuthException {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;
        String uri = request.getRequestURI();
        if (uri == null) {
            uri = URIUtil.SLASH;
        }

        HttpSession session = request.getSession(true);

        try {
            String wa = request.getParameter("wa");
            String wresult = request.getParameter("wresult");
            
            // Handle a request for authentication.
            if (wa != null) {

                FederationResponse wfRes = null;
                if (wa.equals(FederationConstants.ACTION_SIGNIN)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("SignIn request found");
                        LOG.debug("SignIn action...");
                    }

                    if (wresult == null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("SignIn request must contain wresult");
                        }
                        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                        return Authentication.SEND_FAILURE;
                    } else {
                        
                        FederationRequest wfReq = new FederationRequest();
                        wfReq.setWa(wa);
                        wfReq.setWresult(wresult);

                        //Not supported in jetty 7.6
                        //String contextName = request.getServletContext().getContextPath();
                        String contextName = request.getSession().getServletContext().getContextPath();
                        if (contextName == null || contextName.isEmpty()) {
                            contextName = "/";
                        }
                        FederationContext fedConfig = getContextConfiguration(contextName);
                        
                        FederationLoginService fedLoginService = (FederationLoginService)this._loginService;
                        UserIdentity user = fedLoginService.login(null, wfReq, fedConfig);
                        if (user != null)
                        {
                            session=renewSession(request,response);
                            
                            FederationUserIdentity  fui = (FederationUserIdentity)user;
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
                            LOG.debug("WSFED authentication FAILED for " + StringUtil.printable(user.getUserPrincipal().getName()));
                        }
                        if (response != null) {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN);
                        }

                    }
                } else {
                    LOG.warn("Not supported action found in parameter wa: " + wa);
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                    return Authentication.UNAUTHENTICATED;
                }
            }

            // Look for cached authentication
            Authentication authentication = (Authentication) session.getAttribute(SessionAuthentication.__J_AUTHENTICATED);
            if (authentication != null) 
            {
                // Has authentication been revoked?
                if (authentication instanceof Authentication.User && 
                    _loginService!=null &&
                    !_loginService.validate(((Authentication.User)authentication).getUserIdentity()))
                {
                
                    session.removeAttribute(SessionAuthentication.__J_AUTHENTICATED);
                }
                else
                {
                    String j_uri = (String)session.getAttribute(J_URI);
                    if (j_uri != null)
                    {
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
                                Request base_request = (req instanceof Request)?(Request)req:AbstractHttpConnection.getCurrentConnection().getRequest();
                                base_request.setMethod(HttpMethods.POST);
                                base_request.setParameters(j_post);
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
                    
                    if (MimeTypes.FORM_ENCODED.equalsIgnoreCase(req.getContentType()) && HttpMethods.POST.equals(request.getMethod()))
                    {
                        Request base_request = (req instanceof Request)?(Request)req:AbstractHttpConnection.getCurrentConnection().getRequest();
                        base_request.extractParameters();                        
                        session.setAttribute(J_POST, new MultiMap<String>(base_request.getParameters()));
                    }
                }
            }
            
            FederationProcessor wfProc = new FederationProcessorImpl();
            redirectToIssuer(request, response, wfProc);

            return Authentication.SEND_CONTINUE;

        } catch (IOException e) {
            throw new ServerAuthException(e);
        }
        /*
         * catch (ServletException e) { throw new ServerAuthException(e); }
         */
    }



    /* ------------------------------------------------------------ */
    public boolean secureResponse(ServletRequest req, ServletResponse res, boolean mandatory,
                                  User validatedUser) throws ServerAuthException {
        return true;
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
    protected void redirectToIssuer(HttpServletRequest request, HttpServletResponse response, FederationProcessor processor)
        throws IOException {

        //Not supported in jetty 7.6
        //String contextName = request.getServletContext().getContextPath();
        String contextName = request.getSession().getServletContext().getContextPath();
        if (contextName == null || contextName.isEmpty()) {
            contextName = "/";
        }
        FederationContext fedCtx = this.configurator.getFederationContext(contextName);
        String redirectURL = null;
        try {
            redirectURL = processor.createSignInRequest(request, fedCtx);
            if (redirectURL != null) {
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
    
    private FederationContext getContextConfiguration(String contextName) {
        if (configurator == null) {
            throw new IllegalStateException("No Fediz configuration available");
        }
        FederationContext config = configurator.getFederationContext(contextName);
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
