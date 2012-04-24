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

package org.apache.cxf.fediz.service.idp;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.ws.security.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.w3c.dom.Element;

public class IdpServlet extends HttpServlet {

    private static Logger LOG = LoggerFactory.getLogger(IdpServlet.class);

    public static final String PARAM_ACTION = "wa";

    public static final String ACTION_SIGNIN = "wsignin1.0";
    public static final String ACTION_SIGNOUT = "wsignout1.0";
    public static final String ACTION_SIGNOUT_CLEANUP = "wsignoutcleanup1.0";

    public static final String PARAM_WTREALM = "wtrealm";

    public static final String PARAM_WREPLY = "wreply";

    public static final String PARAM_WRESULT = "wresult";

    public static final String PARAM_WCONTEXT = "wctx";

    public static final String AUTH_HEADER_NAME = "WWW-Authenticate";

    public static final String SERVLET_PARAM_TOKENTYPE = "ws-trust-tokentype";

    /**
     * 
     */
    private static final long serialVersionUID = -9019993850246851112L;

    private String tokenType;

    @Override
    public void init() throws ServletException {
        if (getInitParameter("sts.wsdl.url") == null) {
            throw new ServletException(
                "Parameter 'sts.wsdl.url' not configured");
        }
        if (getInitParameter("sts.wsdl.service") == null) {
            throw new ServletException(
                "Parameter 'sts.wsdl.service' not configured");
        }
        if (getInitParameter("sts.wsdl.endpoint") == null) {
            throw new ServletException(
                "Parameter 'sts.wsdl.endpoint' not configured");
        }

        tokenType = getInitParameter(SERVLET_PARAM_TOKENTYPE);
        if (tokenType != null && tokenType.length() > 0) {
            LOG.info("Configured Tokentype: " + tokenType);
        }

    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        /*
         * if (request.getPathInfo().contains("jsp")) { return; }
         */

        String action = request.getParameter(PARAM_ACTION);
        String wtrealm = request.getParameter(PARAM_WTREALM);
        String wctx = request.getParameter(PARAM_WCONTEXT);
        String wreply = request.getParameter(PARAM_WREPLY);

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

            String wresult = null;
            String auth = request.getHeader("Authorization");
            LOG.debug("Authorization header: " + auth);
            if (auth != null) {
                String username = null;
                String password = null;

                try {
                    StringTokenizer st = new StringTokenizer(auth, " ");
                    String authType = st.nextToken();
                    String encoded = st.nextToken();

                    if (authType.equalsIgnoreCase("basic")) {

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
                        LOG.debug("Validating user [" + username
                                  + "] and password [" + password + "]");

                        try {
                            wresult = requestSecurityToken(username, password,
                                                           wtrealm);
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
                            response.sendError(
                                               HttpServletResponse.SC_FORBIDDEN,
                                "Requesting security token failed");
                            return;
                        }

                        LOG.debug("Forward to jsp...");
                        // request.getRequestDispatcher("WEB-INF/signinresponse.jsp").forward(request,
                        // response);
                        // this.getServletContext().getRequestDispatcher("/WEB-INF/signinresponse.jsp").forward(request,
                        // response);
                        this.getServletContext()
                        .getRequestDispatcher(
                            "/WEB-INF/signinresponse.jsp")
                            .forward(request, response);

                    } else {
                        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                            "Invalid Authorization header");
                        return;
                    }
                } catch (Exception ex) {
                    LOG.error("Invalid Authorization header", ex);
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid Authorization header");
                    return;
                }

            } else {
                StringBuilder value = new StringBuilder(16);
                value.append("Basic realm=\"IDP\"");
                response.setHeader(AUTH_HEADER_NAME, value.toString());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameter "
                + PARAM_ACTION + " with value " + action
                + " is not supported");
            return;
        }
    }

    private String requestSecurityToken(String username, String password,
                                        String wtrealm) throws Exception {
        try {
            Bus bus = BusFactory.getDefaultBus();
            List<String> realmClaims = null;
            ApplicationContext ctx = (ApplicationContext) bus
                .getExtension(ApplicationContext.class);
            try {
                Map<String, List<String>> realmClaimsMap = (Map<String, List<String>>) ctx
                    .getBean("realm2ClaimsMap");
                realmClaims = realmClaimsMap.get(wtrealm);
                if (realmClaims != null && realmClaims.size() > 0) {
                    LOG.debug("claims for realm " + wtrealm);
                    for (String item : realmClaims) {
                        LOG.debug("  " + item);
                    }
                }
            } catch (Exception ex) {
                LOG.error("Failed to read bean 'realm2ClaimsMap'", ex);
            }

            IdpSTSClient sts = new IdpSTSClient(bus);
            sts.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
            if (tokenType != null && tokenType.length() > 0) {
                sts.setTokenType(tokenType);
            } else {
                sts.setTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            }
            sts.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");

            sts.setWsdlLocation(getInitParameter("sts.wsdl.url"));
            sts.setServiceQName(new QName(
                                          "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                          getInitParameter("sts.wsdl.service")));
            sts.setEndpointQName(new QName(
                                           "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                           getInitParameter("sts.wsdl.endpoint")));
            sts.getProperties().put(SecurityConstants.USERNAME, username);
            sts.getProperties().put(SecurityConstants.PASSWORD, password);

            Element claims = createClaimsElement(realmClaims);
            if (claims != null) {
                sts.setClaims(claims);
            }
            String rstr = sts.requestSecurityTokenResponse(wtrealm);
            return rstr;
        } catch (org.apache.cxf.binding.soap.SoapFault ex) {
            QName faultCode = ex.getFaultCode();
            if (faultCode.equals(STSException.FAILED_AUTH)) {
                LOG.warn("Failed authentication for '" + username + "'");
            }
            throw ex;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }

    private Element createClaimsElement(List<String> realmClaims)
        throws Exception {
        if (realmClaims == null || realmClaims.size() == 0)
            return null;

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

}
