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
import java.util.List;
import java.util.Map;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.ws.security.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;


public class STSClientFilter extends AbstractAuthFilter {

    private static final String PARAM_TOKENTYPE = "tokentype";

    private static final String PARAM_STS_WSDL_ENDPOINT = "sts.wsdl.endpoint";

    private static final String PARAM_STS_WSDL_SERVICE = "sts.wsdl.service";

    private static final String PARAM_STS_WSDL_URL = "sts.wsdl.url";

    private static final String PARAM_STS_APPLIES_TO = "sts.applies-to";

    private static final String PARAM_STS_CLAIMS_REQUIRED = "sts.claims.required";

    private static final String PARAM_STS_AUTH_TYPE = "sts.auth-type";

    private static final String PARAM_TOKEN_STORE_NAME = "token.store.name";

    //private static final String PARAM_TOKEN_STORE_SESSION = "token.store.session";
    
    private static final String PARAM_RSTR_CONTENT_TYPE = "sts.rstr.content-type";

    private static final String PARAM_STS_ONBEHALFOF_TOKEN_NAME = "sts.onbehalfof.token.name";

    private static final Logger LOG = LoggerFactory.getLogger(STSClientFilter.class);
    
//    static {
//        LOG = LoggerFactory.getLogger(STSClientFilter.class);
//    }
    
    enum AuthenticationType {
        USERNAME_PASSWORD,
        NONE
    }

    protected String tokenType;
    protected String stsWsdlEndpoint;
    protected String stsWsdlService;
    protected String stsWsdlUrl;

    protected String authenticationType;   //Send UsernameToken
    protected boolean claimsRequired; // = false;  //
    protected String onBehalfOfTokenName;  //idp-token
    //protected boolean storeTokenInSession; // = false;
    protected String tokenStoreName;
    protected String appliesTo; // $wtrealm
    protected String contentType;  //token, rstr
    protected boolean isPortSet;

    protected Bus bus;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        tokenType = filterConfig.getInitParameter(PARAM_TOKENTYPE);
        if (tokenType != null && tokenType.length() > 0) {
            LOG.info("Configured Tokentype: " + tokenType);
        }

        stsWsdlUrl = filterConfig.getInitParameter(PARAM_STS_WSDL_URL);
        if (stsWsdlUrl == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_STS_WSDL_URL + "' not configured");
        }
        
        try {
            URL url = new URL(stsWsdlUrl);
            isPortSet = url.getPort() > 0;
            if (!isPortSet) {
                LOG.info("Port is 0 for '" + PARAM_STS_WSDL_URL + "'. Port evaluated when processing first request.");
            }
        } catch (MalformedURLException e) {
            LOG.error("Invalid Url '" + stsWsdlUrl + "': "  + e.getMessage());
        }
        

        stsWsdlService = filterConfig.getInitParameter(PARAM_STS_WSDL_SERVICE);
        if (stsWsdlService == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_STS_WSDL_SERVICE + "' not configured");
        }

        stsWsdlEndpoint = filterConfig.getInitParameter(PARAM_STS_WSDL_ENDPOINT);
        if (stsWsdlEndpoint == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_STS_WSDL_ENDPOINT + "' not configured");
        }

        appliesTo = filterConfig.getInitParameter(PARAM_STS_APPLIES_TO);
        if (appliesTo == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_STS_APPLIES_TO + "' not configured");
        }

        tokenStoreName = filterConfig.getInitParameter(PARAM_TOKEN_STORE_NAME);
        if (tokenStoreName == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_TOKEN_STORE_NAME + "' not configured");
        }

        onBehalfOfTokenName = filterConfig.getInitParameter(PARAM_STS_ONBEHALFOF_TOKEN_NAME);

        try {
            String claimsParam = filterConfig.getInitParameter(PARAM_STS_CLAIMS_REQUIRED);
            if (claimsParam != null) {
                claimsRequired = Boolean.valueOf(claimsParam).booleanValue();
            } else {
                claimsRequired = false;
            }
        } catch (Exception ex) {
            LOG.error("Failed to parse parameter '" + PARAM_STS_CLAIMS_REQUIRED + "': " + ex.toString());
            throw new ServletException(
                                       "Failed to parse parameter '" + PARAM_STS_CLAIMS_REQUIRED + "'");
        }

        /*
        try {
            String storeSession = filterConfig.getInitParameter(PARAM_TOKEN_STORE_SESSION);
            if (storeSession != null) {
                storeTokenInSession = Boolean.valueOf(storeSession).booleanValue();
            } else {
                storeTokenInSession = false;
            }
        } catch (Exception ex) {
            LOG.error("Failed to parse parameter '" + PARAM_TOKEN_STORE_SESSION + "': " + ex.toString());
            throw new ServletException(
                                       "Failed to parse parameter '" + PARAM_TOKEN_STORE_SESSION + "'");
        }
        */

        authenticationType = filterConfig.getInitParameter(PARAM_STS_AUTH_TYPE);
        if (authenticationType == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_STS_AUTH_TYPE + "' not configured");
        }
        
        contentType = filterConfig.getInitParameter(PARAM_RSTR_CONTENT_TYPE);
        if (contentType == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_RSTR_CONTENT_TYPE + "' not configured");
        }
        
        

    }

    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException, ProcessingException {


        String resolvedAppliesTo = null;
        try {
            
            if (context.get(tokenStoreName) != null) {
                LOG.info("Security token '" + tokenStoreName + "' already created.");
                Object token = context.get(tokenStoreName);
                if ((token instanceof SecurityToken)
                    && ((SecurityToken)token).isExpired()) {
                    LOG.info("Security token '" + tokenStoreName + "' has expired.");
                    context.remove(tokenStoreName);
                } else {
                    return;
                }
            }

            Bus cxfBus = getBus();

            IdpSTSClient sts = new IdpSTSClient(cxfBus);
            sts.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
            if (tokenType != null && tokenType.length() > 0) {
                sts.setTokenType(tokenType);
            } else {
                sts.setTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            }
            sts.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
            
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
            sts.setWsdlLocation(stsWsdlUrl);
            sts.setServiceQName(new QName(
                                          "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                          stsWsdlService));
            sts.setEndpointQName(new QName(
                                           "http://docs.oasis-open.org/ws-sx/ws-trust/200512/",
                                           stsWsdlEndpoint));
            String username = null;
            if (AuthenticationType.USERNAME_PASSWORD.name().equals(authenticationType)) {
                username = (String)context.get(AuthContext.AUTH_USERNAME);
                String password = (String)context.get(AuthContext.AUTH_PASSWORD);
                context.remove(AuthContext.AUTH_USERNAME);
                context.remove(AuthContext.AUTH_PASSWORD);
                sts.getProperties().put(SecurityConstants.USERNAME, username);
                sts.getProperties().put(SecurityConstants.PASSWORD, password);
            }


            /*
            if (getInitParameter(S_PARAM_TOKEN_INTERNAL_LIFETIME) != null) {
                sts.setEnableLifetime(true);
                int ttl = Integer.parseInt(getInitParameter(S_PARAM_TOKEN_INTERNAL_LIFETIME));
                sts.setTtl(ttl);
            }
             */


            if (appliesTo.startsWith("$")) {
                resolvedAppliesTo = (String)context.get(appliesTo.substring(1));
                if (resolvedAppliesTo == null) {
                    LOG.error("Parameter '" + appliesTo.substring(1) + "' not found in context");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                       "Parameter '" + appliesTo.substring(1) + "' not found in context");
                    throw new ProcessingException("Parameter '" + appliesTo.substring(1) + "' not found in context");
                }
            } else {
                resolvedAppliesTo = appliesTo;
            }

            if (this.claimsRequired) {
                List<String> realmClaims = null;
                ApplicationContext ctx = (ApplicationContext) cxfBus
                .getExtension(ApplicationContext.class);
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, List<String>> realmClaimsMap = (Map<String, List<String>>) ctx
                    .getBean("realm2ClaimsMap");
                    realmClaims = realmClaimsMap.get(resolvedAppliesTo);
                    if (realmClaims != null && realmClaims.size() > 0 && LOG.isDebugEnabled()) {
                        LOG.debug("claims for realm " + resolvedAppliesTo);
                        for (String item : realmClaims) {
                            LOG.debug("  " + item);
                        }
                    }
                    Element claims = createClaimsElement(realmClaims);
                    if (claims != null) {
                        sts.setClaims(claims);
                    }

                } catch (Exception ex) {
                    LOG.error("Failed to read bean 'realm2ClaimsMap'", ex);
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                       "Failed to read bean 'realm2ClaimsMap'");
                    throw new ProcessingException("Failed to read bean 'realm2ClaimsMap'");
                }
            }

            if (this.onBehalfOfTokenName != null) {
                SecurityToken token = (SecurityToken)context.get(onBehalfOfTokenName);
                if (token == null) {
                    LOG.error("Token '" + onBehalfOfTokenName + "' not found");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                       "Token '" + onBehalfOfTokenName + "' not found");
                    throw new ProcessingException("Token '" + onBehalfOfTokenName + "' not found");
                }
                sts.setOnBehalfOf(token.getToken());
            }

            Object token = null;
            if (contentType != null && contentType.equalsIgnoreCase("TOKEN")) {
                token = sts.requestSecurityToken(resolvedAppliesTo);
            } else if (contentType != null && contentType.equalsIgnoreCase("RSTR")) {
                token = sts.requestSecurityTokenResponse(resolvedAppliesTo);
            } else {
                LOG.error("Unknown content type '" + contentType + "'");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                   "Unknown content type '" + contentType + "'");
                throw new ProcessingException("Unknown content type '" + contentType + "'");
            }

            //[TODO] SessionCacheFilter, use this filter instead of code here
            /* not needed anymore due to SessionCacheFilter
            if (this.storeTokenInSession) {
                request.getSession().setAttribute(tokenStoreName, token);
                LOG.info("Token '" + tokenStoreName + "' stored in session.");
            } else {
                context.put(tokenStoreName, token);
                LOG.info("Token '" + tokenStoreName + "' stored in request.");
            }*/
            context.put(tokenStoreName, token);
            LOG.info("Token '" + tokenStoreName + "' stored in request.");
            
            if (username != null) {
                context.put(AuthContext.IDP_PRINCIPAL, username);
            }
            

        } catch (Exception ex) {
            LOG.info("Requesting security token for '" + resolvedAppliesTo + "' failed", ex);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                               "Requesting security token for '" + resolvedAppliesTo + "'failed");
            throw new ProcessingException("Requesting security token for '" + resolvedAppliesTo + "' failed");
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
    
    private synchronized void setSTSWsdlUrl(String wsdlUrl) {
        this.stsWsdlUrl = wsdlUrl;
        this.isPortSet = true;
    }

    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public Bus getBus() {
        // do not store a referance to the default bus
        return (bus != null) ? bus : BusFactory.getDefaultBus();
    }
}
