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

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FederationFilter extends AbstractAuthFilter {

    public static final String PARAM_ACTION = "wa";

    public static final String ACTION_SIGNIN = "wsignin1.0";

    public static final String ACTION_SIGNOUT = "wsignout1.0";

    public static final String ACTION_SIGNOUT_CLEANUP = "wsignoutcleanup1.0";

    public static final String PARAM_WTREALM = "wtrealm";

    public static final String PARAM_WREPLY = "wreply";

    public static final String PARAM_WRESULT = "wresult";

    public static final String PARAM_WCONTEXT = "wctx";

    public static final String PARAM_WFRESH = "wfresh";

    public static final String PARAM_WAUTH = "wauth";
    
    public static final String PARAM_SESSION_TOKEN = "session.token";

    private static final Logger LOG = LoggerFactory.getLogger(FederationFilter.class);
    
    
    private String sessionToken;
//    static {
//        LOG = LoggerFactory.getLogger(FederationFilter.class);
//    }
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        
        sessionToken = filterConfig.getInitParameter(PARAM_SESSION_TOKEN);
        if (sessionToken != null && sessionToken.length() > 0) {
            LOG.info("Configured Session token: " + sessionToken);
        }
    }

    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException, ProcessingException {


        String action = request.getParameter(PARAM_ACTION);
        String wtrealm = request.getParameter(PARAM_WTREALM);
        String wctx = request.getParameter(PARAM_WCONTEXT);
        String wreply = request.getParameter(PARAM_WREPLY);
        String wfresh = request.getParameter(PARAM_WFRESH);
        String wauth = request.getParameter(PARAM_WAUTH);

        if (action == null) {
            //[TODO] should not fail because other filter might be relevant
            //Initial session state (AUTHENTICATED) ignored, but STSClientFilter requires SECURITY_TOKEN_REQUIRED
            LOG.info("Not a WS-Federation request");
            return;
            /* LOG.error("Bad request. HTTP parameter '" + PARAM_ACTION
                      + "' missing");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameter "
                               + PARAM_ACTION + " missing");
            throw new ProcessingException("Bad request. HTTP parameter '" + PARAM_ACTION
                                          + "' missing");
                                          */
        }
        if (action.equals(ACTION_SIGNIN)) {
            LOG.debug("Sign-In request [" + PARAM_ACTION + "=" + ACTION_SIGNIN
                      + "] ...");

            if (wtrealm == null || wtrealm.length() == 0) {
                LOG.error("Bad request. HTTP parameter '" + ACTION_SIGNIN
                          + "' missing");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                                   "Parameter " + ACTION_SIGNIN + " missing");
                throw new ProcessingException("Bad request. HTTP parameter '" + ACTION_SIGNIN
                                              + "' missing");
            }
            boolean authenticationRequired = false;

            context.put(PARAM_WCONTEXT, wctx);
            context.put(PARAM_WTREALM, wtrealm);
            context.put(PARAM_WREPLY, wreply);
            context.put(PARAM_WAUTH, wauth);
            context.put(PARAM_ACTION, action);
            context.put(PARAM_WFRESH, wfresh);


            SecurityToken idpToken = null;
            idpToken = (SecurityToken)context.get(sessionToken);
            String user = (String)context.get(AuthContext.IDP_PRINCIPAL);
            if (idpToken == null) {
                LOG.debug("IDP token not found");
                authenticationRequired = true;
            } else {
                if (idpToken.isExpired()) {
                    LOG.info("IDP token of '" + user + "' expired. Require authentication.");
                    authenticationRequired = idpToken.isExpired();
                } else if (wfresh != null && wfresh.equals("0")) {
                    LOG.info("IDP token of '" + user + "' valid but relying party requested new authentication");
                    authenticationRequired = true;
                } else {
                    LOG.debug("Session found for '" + user + "'.");
                    //Add it to the request context
                    context.put(sessionToken, idpToken);
                    context.put(AuthContext.IDP_PRINCIPAL, user);
                }
            }
            if (authenticationRequired) {
                context.remove(sessionToken);
                this.setNextState(States.AUTHENTICATION_REQUIRED.toString(), context);
            } else {
                this.setNextState(States.SECURITY_TOKEN_REQUIRED.toString(), context);
            }

        }
    }



}
