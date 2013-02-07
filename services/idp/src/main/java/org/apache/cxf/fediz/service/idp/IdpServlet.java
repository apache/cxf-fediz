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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.ws.security.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

public class IdpServlet extends HttpServlet {
    
    public static final String PARAM_ACTION = "wa";

    public static final String ACTION_SIGNIN = "wsignin1.0";
    public static final String ACTION_SIGNOUT = "wsignout1.0";
    public static final String ACTION_SIGNOUT_CLEANUP = "wsignoutcleanup1.0";

    public static final String PARAM_WTREALM = "wtrealm";

    public static final String PARAM_WREPLY = "wreply";

    public static final String PARAM_WRESULT = "wresult";

    public static final String PARAM_WCONTEXT = "wctx";
    
    public static final String PARAM_WFRESH = "wfresh";

    public static final String AUTH_HEADER_NAME = "WWW-Authenticate";

    public static final String SERVLET_PARAM_TOKENTYPE = "ws-trust-tokentype";
    
    public static final String IDP_TOKEN = "idp-token";
    
    public static final String IDP_USER = "idp-user";
    
    private static final Logger LOG = LoggerFactory.getLogger(IdpServlet.class);
    
    private static final String S_PARAM_TOKEN_INTERNAL_LIFETIME = "token.internal.lifetime";

    private static final String S_PARAM_STS_RP_URI = "sts.RP.uri";

    private static final String S_PARAM_STS_UT_URI = "sts.UT.uri";

    private static final String S_PARAM_STS_RP_WSDL_ENDPOINT = "sts.RP.wsdl.endpoint";

    private static final String S_PARAM_STS_UT_WSDL_ENDPOINT = "sts.UT.wsdl.endpoint";

    private static final String S_PARAM_STS_WSDL_SERVICE = "sts.wsdl.service";

    private static final String S_PARAM_STS_WSDL_URL = "sts.wsdl.url";
    
    private static final String S_PARAM_STS_USE_WFRESH_FOR_TTL = "sts.use.wfresh.for.ttl";


    /**
     * 
     */
    private static final long serialVersionUID = -9019993850246851112L;

    protected boolean isPortSet;
    
    protected String stsWsdlUrl;
    
    protected boolean useWfreshForTTL;
    
    private String tokenType;

    private Bus bus;

    @Override
    public void init() throws ServletException {
        stsWsdlUrl = getInitParameter(S_PARAM_STS_WSDL_URL);
        if (stsWsdlUrl == null) {
            throw new ServletException(
                "Parameter '" + S_PARAM_STS_WSDL_URL + "' not configured");
        }
        try {
            URL url = new URL(stsWsdlUrl);
            isPortSet = url.getPort() > 0;
            if (!isPortSet) {
                LOG.info("Port is 0 for '" + S_PARAM_STS_WSDL_URL + "'. Port evaluated when processing first request.");
            }
        } catch (MalformedURLException e) {
            LOG.error("Invalid Url '" + stsWsdlUrl + "': "  + e.getMessage());
        }
        if (getInitParameter(S_PARAM_STS_WSDL_SERVICE) == null) {
            throw new ServletException(
                "Parameter '" + S_PARAM_STS_WSDL_SERVICE + "' not configured");
        }
        if (getInitParameter(S_PARAM_STS_UT_WSDL_ENDPOINT) == null) {
            throw new ServletException(
                "Parameter '" + S_PARAM_STS_UT_WSDL_ENDPOINT + "' not configured");
        }
        if (getInitParameter(S_PARAM_STS_RP_WSDL_ENDPOINT) == null) {
            throw new ServletException(
                "Parameter '" + S_PARAM_STS_RP_WSDL_ENDPOINT + "' not configured");
        }
        if (getInitParameter(S_PARAM_STS_UT_URI) == null) {
            throw new ServletException(
                "Parameter '" + S_PARAM_STS_UT_URI + "' not configured");
        }
        if (getInitParameter(S_PARAM_STS_RP_URI) == null) {
            throw new ServletException(
                "Parameter '" + S_PARAM_STS_RP_URI + "' not configured");
        } 

        tokenType = getInitParameter(SERVLET_PARAM_TOKENTYPE);
        if (tokenType != null && tokenType.length() > 0) {
            LOG.info("Configured Tokentype: " + tokenType);
        }
        if (getInitParameter(S_PARAM_TOKEN_INTERNAL_LIFETIME) != null) {
            LOG.info("Configured token lifetime: " + getInitParameter(S_PARAM_TOKEN_INTERNAL_LIFETIME));
        }
        
        try {
            String wfreshParam = getInitParameter(S_PARAM_STS_USE_WFRESH_FOR_TTL);
            if (wfreshParam != null) {
                useWfreshForTTL = Boolean.valueOf(wfreshParam).booleanValue();
            } else {
                useWfreshForTTL = true;
            }
        } catch (Exception ex) {
            LOG.error("Failed to parse parameter '" + S_PARAM_STS_USE_WFRESH_FOR_TTL + "': " 
                + ex.toString());
            throw new ServletException("Failed to parse parameter '" 
                + S_PARAM_STS_USE_WFRESH_FOR_TTL + "'");
        }

    }

    //CHECKSTYLE:OFF
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        if (!isPortSet) {
            try {
                URL url = new URL(stsWsdlUrl);
                URL updatedUrl = new URL(url.getProtocol(), url.getHost(), request.getLocalPort(), url.getFile());
                setSTSWsdlUrl(updatedUrl.toString());
                LOG.info("STS WSDL URL updated to " + updatedUrl.toString());
            } catch (MalformedURLException e) {
                LOG.error("Invalid Url '" + stsWsdlUrl + "': "  + e.getMessage());
            }
        }

        String action = request.getParameter(PARAM_ACTION);
        String wtrealm = request.getParameter(PARAM_WTREALM);
        String wctx = request.getParameter(PARAM_WCONTEXT);
        String wreply = request.getParameter(PARAM_WREPLY);
        String wfresh = request.getParameter(PARAM_WFRESH);

        if (action == null) {
            LOG.error("Bad request. HTTP parameter '" + PARAM_ACTION
                      + "' missing");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameter "
                + PARAM_ACTION + " missing");
            return;
        }
        if (action.equals(ACTION_SIGNIN)) {
            LOG.debug("Sign-In request [" + PARAM_ACTION + "=" + ACTION_SIGNIN
                      + "] ...");

            if (wtrealm == null || wtrealm.length() == 0) {
                LOG.error("Bad request. HTTP parameter '" + ACTION_SIGNIN
                          + "' missing");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                                   "Parameter " + ACTION_SIGNIN + " missing");
                return;
            }
            boolean authenticationRequired = false;
            SecurityToken idpToken = null;
            HttpSession session = request.getSession(false);
            if (session != null) {
                idpToken = (SecurityToken)session.getAttribute(IDP_TOKEN);
                String user = (String)session.getAttribute(IDP_USER);
                if (idpToken == null) {
                    LOG.error("IDP token not found");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "IDP token not found");
                    return;
                } else {
                    if (idpToken.isExpired()) {
                        LOG.info("IDP token of '" + user + "' expired. Require authentication.");
                        authenticationRequired = idpToken.isExpired();
                    } else if (wfresh != null) {
                        authenticationRequired = parseWfresh(wfresh, user, idpToken);
                    }
                    
                    if (!authenticationRequired) {
                        LOG.debug("Session found for '" + user + "'.");
                    }
                }
            } else {
                authenticationRequired = true;
            }
            
            if (authenticationRequired) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authentication required ...");
                }
                String auth = request.getHeader("Authorization");
                LOG.debug("Authorization header: " + auth);
                
                if (auth == null) {
                    // request authentication from browser
                    StringBuilder value = new StringBuilder(16);
                    value.append("Basic realm=\"IDP\"");
                    response.setHeader(AUTH_HEADER_NAME, value.toString());
                    response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } else {
                    String username = null;
                    String password = null;
    
                    try {
                        StringTokenizer st = new StringTokenizer(auth, " ");
                        String authType = st.nextToken();
                        String encoded = st.nextToken();
    
                        if (!authType.equalsIgnoreCase("basic")) {
                            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Authorization header");
                            return;
                        }
    
                        String decoded = new String(
                                                    Base64Utility.decode(encoded));
    
                        int colon = decoded.indexOf(':');
                        if (colon < 0) {
                            username = decoded;
                        } else {
                            username = decoded.substring(0, colon);
                            password = decoded.substring(colon + 1,
                                                         decoded.length());
                        }
                        if (LOG.isInfoEnabled()) {
                            LOG.info("Validating user '" + username + "'...");    
                        }
                        
                        try {
                            idpToken = 
                                requestSecurityTokenForIDP(username, password, "urn:fediz:idp", wfresh);
                            session = request.getSession(true);
                            session.setAttribute(IDP_TOKEN, idpToken);
                            session.setAttribute(IDP_USER, username);
                        } catch (Exception ex) {
                            LOG.info("Requesting IDP security token failed", ex);
                            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                                "Requesting IDP security token failed");
                            return;
                        }
                    } catch (Exception ex) {
                        LOG.error("Invalid Authorization header", ex);
                        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                            "Invalid Authorization header");
                        return;
                    }
                
                }
            }                

            
            // Get token on-behalf-of the IDP token
            String wresult = null;
            String user = (String)session.getAttribute(IDP_USER);
            if (LOG.isInfoEnabled()) {
                LOG.info("Requesting token on-behalf-of '" + user + "' for relying party '" + wtrealm);
            }

            try {
                wresult = requestSecurityTokenForRP(idpToken, wtrealm);
                request.setAttribute("fed." + PARAM_WRESULT,
                                     StringEscapeUtils.escapeXml(wresult));
                if (wctx != null) {
                    request.setAttribute("fed." + PARAM_WCONTEXT,
                                         StringEscapeUtils.escapeXml(wctx));
                }
                if (wreply == null) {
                    request.setAttribute("fed.action", wtrealm);
                } else {
                    request.setAttribute("fed.action", wreply);
                }
            } catch (Exception ex) {
                LOG.info("Requesting security token failed", ex);
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "Requesting security token failed");
                return;
            }

            LOG.debug("Forward to jsp...");
            response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
            this.getServletContext().getRequestDispatcher("/WEB-INF/signinresponse.jsp")
                .forward(request, response);
            
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameter "
                + PARAM_ACTION + " with value " + action
                + " is not supported");
            return;
        }
    }
    
    private SecurityToken requestSecurityTokenForIDP(
        String username, String password, String appliesTo, String wfresh
    ) throws Exception {
        Bus cxfBus = getBus();
        
        IdpSTSClient sts = new IdpSTSClient(cxfBus);
        sts.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
        if (tokenType != null && tokenType.length() > 0) {
            sts.setTokenType(tokenType);
        } else {
            sts.setTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
        }
        sts.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");

        sts.setWsdlLocation(this.stsWsdlUrl + getInitParameter(S_PARAM_STS_UT_URI) + "?wsdl");
        sts.setServiceQName(new QName(
                                      "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                      getInitParameter(S_PARAM_STS_WSDL_SERVICE)));
        sts.setEndpointQName(new QName(
                                       "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                       getInitParameter(S_PARAM_STS_UT_WSDL_ENDPOINT)));
        sts.getProperties().put(SecurityConstants.USERNAME, username);
        sts.getProperties().put(SecurityConstants.PASSWORD, password);
        
        configureTTL(sts, wfresh);

        return sts.requestSecurityToken(appliesTo);
    }
    
    private void configureTTL(IdpSTSClient sts, String wfresh) {
        if (wfresh != null) {
            try {
                int ttl = Integer.parseInt(wfresh);
                if (ttl > 0) {
                    sts.setTtl(ttl * 60);                    
                    sts.setEnableLifetime(true);
                    return;
                }
            } catch (NumberFormatException ex) {
                LOG.error("Invalid wfresh value '" + wfresh + "': "  + ex.getMessage());
            }
        }
        
        // wfresh not set so fall back to a configured value
        if (getInitParameter(S_PARAM_TOKEN_INTERNAL_LIFETIME) != null) {
            sts.setEnableLifetime(true);
            int ttl = Integer.parseInt(getInitParameter(S_PARAM_TOKEN_INTERNAL_LIFETIME));
            sts.setTtl(ttl);
        }
    }

    private String requestSecurityTokenForRP(SecurityToken onbehalfof,
                                        String appliesTo) throws Exception {
        try {
            Bus cxfBus = getBus();
            List<String> realmClaims = null;
            ApplicationContext ctx = (ApplicationContext) cxfBus
                .getExtension(ApplicationContext.class);
            try {
                @SuppressWarnings("unchecked")
                Map<String, List<String>> realmClaimsMap = (Map<String, List<String>>) ctx
                    .getBean("realm2ClaimsMap");
                realmClaims = realmClaimsMap.get(appliesTo);
                if (realmClaims != null && realmClaims.size() > 0 && LOG.isDebugEnabled()) {
                    LOG.debug("claims for realm " + appliesTo);
                    for (String item : realmClaims) {
                        LOG.debug("  " + item);
                    }
                }
            } catch (Exception ex) {
                LOG.error("Failed to read bean 'realm2ClaimsMap'", ex);
            }

            IdpSTSClient sts = new IdpSTSClient(cxfBus);
            sts.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
            if (tokenType != null && tokenType.length() > 0) {
                sts.setTokenType(tokenType);
            } else {
                sts.setTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            }
            sts.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");

            sts.setWsdlLocation(this.stsWsdlUrl + getInitParameter(S_PARAM_STS_RP_URI) + "?wsdl");
            sts.setServiceQName(new QName(
                                          "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                          getInitParameter(S_PARAM_STS_WSDL_SERVICE)));
            sts.setEndpointQName(new QName(
                                           "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                           getInitParameter(S_PARAM_STS_RP_WSDL_ENDPOINT)));
            
            sts.setOnBehalfOf(onbehalfof.getToken());
            
            Element claims = createClaimsElement(realmClaims);
            if (claims != null) {
                sts.setClaims(claims);
            }
            return sts.requestSecurityTokenResponse(appliesTo);
        } catch (org.apache.cxf.binding.soap.SoapFault ex) {
            QName faultCode = ex.getFaultCode();
            if (faultCode.equals(STSException.FAILED_AUTH)) {
                LOG.warn("Failed authentication for '" + onbehalfof.getPrincipal().getName() + "'");
            }
            throw ex;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }

    private Element createClaimsElement(List<String> realmClaims)
        throws Exception {
        if (realmClaims == null || realmClaims.size() == 0) {
            return null;
        }

        W3CDOMStreamWriter writer = new W3CDOMStreamWriter();
        writer.writeStartElement("wst", "Claims", STSUtils.WST_NS_05_12);
        writer.writeNamespace("wst", STSUtils.WST_NS_05_12);
        writer.writeNamespace("ic",
            "http://schemas.xmlsoap.org/ws/2005/05/identity");
        writer.writeAttribute("Dialect",
            "http://schemas.xmlsoap.org/ws/2005/05/identity");

        if (realmClaims != null && realmClaims.size() > 0) {
            for (String item : realmClaims) {
                LOG.debug("claim: " + item);
                writer.writeStartElement("ic", "ClaimType",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity");
                writer.writeAttribute("Uri", item);
                writer.writeEndElement();
            }
        }

        writer.writeEndElement();

        return writer.getDocument().getDocumentElement();
    }
    
    /*
     * Return true if authentication is required after parsing wfresh
     */
    private boolean parseWfresh(String wfresh, String user, SecurityToken idpToken) {
        if ("0".equals(wfresh)) {
            LOG.info("IDP token of '" + user + "' valid but relying party requested new authentication");
            return true;
        } else {
            long ttl = Long.parseLong(wfresh);
            if (ttl > 0) {
                Date createdDate = idpToken.getCreated();
                Date expiryDate = new Date();
                expiryDate.setTime(createdDate.getTime() + (ttl * 60L * 1000L));
                if (expiryDate.before(new Date())) {
                    LOG.info("IDP token of '" + user 
                             + "' valid but relying party requested new authentication via wfresh: " + wfresh);
                    return true;
                }
            } else {
                LOG.info("wfresh value of " + wfresh + " is invalid");
            }
        }
        return false;
    }
    
    private synchronized void setSTSWsdlUrl(String wsdlUrl) {
        this.stsWsdlUrl = wsdlUrl;
        this.isPortSet = true;
    }

    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public Bus getBus() {
        return (bus != null) ? bus : BusFactory.getDefaultBus();
    }
}
