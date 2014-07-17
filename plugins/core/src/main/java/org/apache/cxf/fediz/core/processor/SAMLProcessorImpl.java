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

package org.apache.cxf.fediz.core.processor;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.zip.DataFormatException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.TokenValidatorRequest;
import org.apache.cxf.fediz.core.TokenValidatorResponse;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.metadata.MetadataWriter;
import org.apache.cxf.fediz.core.samlsso.AuthnRequestBuilder;
import org.apache.cxf.fediz.core.samlsso.CompressionUtils;
import org.apache.cxf.fediz.core.samlsso.RequestState;
import org.apache.cxf.fediz.core.samlsso.SAMLProtocolResponseValidator;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLProcessorImpl implements FedizProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLProcessorImpl.class);
    
    static {
        OpenSAMLUtil.initSamlEngine();
    }

    /**
     * Default constructor
     */
    public SAMLProcessorImpl() {
        super();
    }

    @Override
    public FedizResponse processRequest(FedizRequest request,
                                             FedizContext config)
        throws ProcessingException {
        
        if (!(config.getProtocol() instanceof SAMLProtocol)) {
            LOG.error("Unsupported protocol");
            throw new IllegalStateException("Unsupported protocol");
        }
        
        if (request.getResponseToken() == null || request.getState() == null) {
            LOG.error("Missing response token or RelayState parameters");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        
        return processSignInRequest(request, config);
    }
    

    public Document getMetaData(FedizContext config) throws ProcessingException {
        return new MetadataWriter().getMetaData(config);
    }
    /*
    private RequestState processRelayState(String relayState, SAMLProtocol samlProtocol) 
        throws ProcessingException {
        if (relayState.getBytes().length < 0 || relayState.getBytes().length > 80) {
            LOG.error("Invalid RelayState");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        RequestState requestState = samlProtocol.getStateManager().removeRequestState(relayState);
        if (requestState == null) {
            LOG.error("Missing Request State");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        if (isStateExpired(requestState.getCreatedAt(), 0, samlProtocol.getStateTimeToLive())) {
            LOG.error("EXPIRED_REQUEST_STATE");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        return requestState;
    }
    
    private boolean isStateExpired(long stateCreatedAt, long expiresAt, long stateTTL) {
        Date currentTime = new Date();
        if (currentTime.after(new Date(stateCreatedAt + stateTTL))) {
            return true;
        }
        
        if (expiresAt > 0 && currentTime.after(new Date(expiresAt))) {
            return true;
        }
        
        return false;
    }
    */
    protected FedizResponse processSignInRequest(
            FedizRequest request, FedizContext config)
        throws ProcessingException {
        SAMLProtocol protocol = (SAMLProtocol)config.getProtocol();
        // TODO RequestState requestState = processRelayState(request.getState(), protocol);
        
        InputStream tokenStream = null;
        try {
            byte[] deflatedToken = Base64.decode(request.getResponseToken());
            tokenStream = CompressionUtils.inflate(deflatedToken); 
        } catch (DataFormatException ex) {
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        } catch (Base64DecodingException e) {
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        Document doc = null;
        Element el = null;
        try {
            doc = DOMUtils.readXml(tokenStream);
            el = doc.getDocumentElement();

        } catch (Exception e) {
            LOG.warn("Failed to parse token: " + e.getMessage());
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        
        LOG.debug("Received response: " + DOM2Writer.nodeToString(el));
        
        XMLObject responseObject = null;
        try {
            responseObject = OpenSAMLUtil.fromDom(el);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        if (!(responseObject instanceof org.opensaml.saml2.core.Response)) {
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        
        // Validate the Response
        validateSamlResponseProtocol((org.opensaml.saml2.core.Response)responseObject);
        
        // Validate the internal assertion(s)
        TokenValidatorResponse validatorResponse = null;
        List<Element> assertions = 
            DOMUtils.getChildrenWithName(el, SAMLConstants.SAML20_NS, "Assertion");
        
        if (assertions.isEmpty()) {
            LOG.debug("No Assertion extracted from SAML Response");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        Element token = assertions.get(0);
            
        List<TokenValidator> validators = protocol.getTokenValidators();
        for (TokenValidator validator : validators) {
            boolean canHandle = validator.canHandleToken(token);
            if (canHandle) {
                try {
                    TokenValidatorRequest validatorRequest = 
                        new TokenValidatorRequest(token, request.getCerts());
                    validatorResponse = validator.validateAndProcessToken(validatorRequest, config);
                } catch (ProcessingException ex) {
                    throw ex;
                } catch (Exception ex) {
                    LOG.warn("Failed to validate token", ex);
                    throw new ProcessingException(TYPE.TOKEN_INVALID);
                }
                break;
            } else {
                LOG.warn("No security token validator found for '" + token.getLocalName() + "'");
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
        }
        
        /* TODO
        SSOValidatorResponse validatorResponse = 
            validateSamlSSOResponse(postBinding, samlResponse, requestState);
            */
        
        FedizResponse fedResponse = new FedizResponse(
                validatorResponse.getUsername(), validatorResponse.getIssuer(),
                validatorResponse.getRoles(), validatorResponse.getClaims(),
                validatorResponse.getAudience(),
                null, // TODO
                null, // TODO
                token,
                validatorResponse.getUniqueTokenId());

        return fedResponse;
    }
    
    /**
     * Validate the received SAML Response as per the protocol
     * @throws ProcessingException 
     */
    protected void validateSamlResponseProtocol(
        org.opensaml.saml2.core.Response samlResponse
    ) throws ProcessingException {
        try {
            SAMLProtocolResponseValidator protocolValidator = new SAMLProtocolResponseValidator();
            protocolValidator.validateSamlResponse(samlResponse);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
    }
    
    /**
     * Validate the received SAML Response as per the Web SSO profile
    protected SSOValidatorResponse validateSamlSSOResponse(
        boolean postBinding,
        org.opensaml.saml2.core.Response samlResponse,
        RequestState requestState
    ) {
        try {
            SAMLSSOResponseValidator ssoResponseValidator = new SAMLSSOResponseValidator();
            ssoResponseValidator.setAssertionConsumerURL(
                messageContext.getUriInfo().getAbsolutePath().toString());

            ssoResponseValidator.setClientAddress(
                 messageContext.getHttpServletRequest().getRemoteAddr());

            ssoResponseValidator.setIssuerIDP(requestState.getIdpServiceAddress());
            ssoResponseValidator.setRequestId(requestState.getSamlRequestId());
            ssoResponseValidator.setSpIdentifier(requestState.getIssuerId());
            ssoResponseValidator.setEnforceAssertionsSigned(enforceAssertionsSigned);
            ssoResponseValidator.setEnforceKnownIssuer(enforceKnownIssuer);
            ssoResponseValidator.setReplayCache(getReplayCache());

            return ssoResponseValidator.validateSamlResponse(samlResponse, postBinding);
        } catch (WSSecurityException ex) {
            reportError("INVALID_SAML_RESPONSE");
            throw ExceptionUtils.toBadRequestException(ex, null);
        }
    }
    */

    @Override
    public RedirectionResponse createSignInRequest(HttpServletRequest request, FedizContext config)
        throws ProcessingException {

        String redirectURL = null;
        try {
            if (!(config.getProtocol() instanceof SAMLProtocol)) {
                LOG.error("Unsupported protocol");
                throw new IllegalStateException("Unsupported protocol");
            }
            
            String issuerURL = resolveIssuer(request, config);
            LOG.info("Issuer url: " + issuerURL);
            if (issuerURL != null && issuerURL.length() > 0) {
                redirectURL = issuerURL;
            }
            
            AuthnRequestBuilder authnRequestBuilder = 
                ((SAMLProtocol)config.getProtocol()).getAuthnRequestBuilder();
            
            Document doc = DOMUtils.createDocument();
            doc.appendChild(doc.createElement("root"));
     
            // Create the AuthnRequest
            String requestURL = request.getRequestURL().toString();
            AuthnRequest authnRequest = 
                authnRequestBuilder.createAuthnRequest(config.getName(), requestURL);
            
            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                authnRequest.setDestination(redirectURL);
            }
            
            Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
            String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);
            
            String webAppDomain = ((SAMLProtocol)config.getProtocol()).getWebAppDomain();
            
            RequestState requestState = new RequestState(requestURL,
                                                         redirectURL,
                                                         authnRequest.getID(),
                                                         config.getName(),
                                                         requestURL,
                                                         webAppDomain,
                                                         System.currentTimeMillis());
            
            String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
            ((SAMLProtocol)config.getProtocol()).getStateManager().setRequestState(relayState, requestState);
            
            String urlEncodedRequest = 
                URLEncoder.encode(authnRequestEncoded, "UTF-8");
            
            StringBuilder sb = new StringBuilder();
            sb.append("SAMLRequest").append('=').append(urlEncodedRequest);
            sb.append("&RelayState").append('=').append(relayState);
            
            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                // TODO Sign the request
            }
            
            String contextCookie = createCookie("RelayState",
                                                relayState,
                                                request.getRequestURI(),
                                                webAppDomain,
                                                ((SAMLProtocol)config.getProtocol()).getStateTimeToLive());
            
            RedirectionResponse response = new RedirectionResponse();
            response.addHeader("Set-Cookie", contextCookie);
            response.addHeader("Cache-Control", "no-cache, no-store");
            response.addHeader("Pragma", "no-cache");
            
            redirectURL = redirectURL + "?" + sb.toString();
            response.setRedirectionURL(redirectURL);
            
            return response;
        } catch (Exception ex) {
            LOG.error("Failed to create SignInRequest", ex);
            throw new ProcessingException("Failed to create SignInRequest");
        }
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
        String cookieExpires = getHttpDateFormat().format(expiresDate);
        contextCookie += ";Expires=" + cookieExpires;
        
        return contextCookie;
    }
    
    protected static SimpleDateFormat getHttpDateFormat() {
        SimpleDateFormat dateFormat =
            new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        TimeZone tZone = TimeZone.getTimeZone("GMT");
        dateFormat.setTimeZone(tZone);
        return dateFormat;
    }
    
    protected String encodeAuthnRequest(Element authnRequest) throws IOException {
        String requestMessage = DOM2Writer.nodeToString(authnRequest);

        byte[] deflatedBytes = CompressionUtils.deflate(requestMessage.getBytes("UTF-8"));

        return Base64.encode(deflatedBytes);
    }

    @Override
    public RedirectionResponse createSignOutRequest(HttpServletRequest request, FedizContext config)
        throws ProcessingException {

        String redirectURL = null;
        try {
            if (!(config.getProtocol() instanceof FederationProtocol)) {
                LOG.error("Unsupported protocol");
                throw new IllegalStateException("Unsupported protocol");
            }

            String issuerURL = resolveIssuer(request, config);
            LOG.info("Issuer url: " + issuerURL);
            if (issuerURL != null && issuerURL.length() > 0) {
                redirectURL = issuerURL;
            }

            StringBuilder sb = new StringBuilder();
            sb.append(FederationConstants.PARAM_ACTION).append('=').append(FederationConstants.ACTION_SIGNOUT);

            String logoutRedirectTo = config.getLogoutRedirectTo();
            if (logoutRedirectTo != null && !logoutRedirectTo.isEmpty()) {

                if (logoutRedirectTo.startsWith("/")) {
                    logoutRedirectTo = extractFullContextPath(request).concat(logoutRedirectTo.substring(1));
                } else {
                    logoutRedirectTo = extractFullContextPath(request).concat(logoutRedirectTo);
                }

                LOG.debug("wreply=" + logoutRedirectTo);

                sb.append('&').append(FederationConstants.PARAM_REPLY).append('=');
                sb.append(URLEncoder.encode(logoutRedirectTo, "UTF-8"));
            }

            redirectURL = redirectURL + "?" + sb.toString();
        } catch (Exception ex) {
            LOG.error("Failed to create SignInRequest", ex);
            throw new ProcessingException("Failed to create SignInRequest");
        }
        
        RedirectionResponse response = new RedirectionResponse();
        response.setRedirectionURL(redirectURL);
        return response;
    }
/*
    private String resolveSignInQuery(HttpServletRequest request, FedizContext config)
        throws IOException, UnsupportedCallbackException, UnsupportedEncodingException {
        Object signInQueryObj = ((FederationProtocol)config.getProtocol()).getSignInQuery();
        String signInQuery = null;
        if (signInQueryObj != null) {
            if (signInQueryObj instanceof String) {
                signInQuery = (String)signInQueryObj;
            } else if (signInQueryObj instanceof CallbackHandler) {
                CallbackHandler frCB = (CallbackHandler)signInQueryObj;
                SignInQueryCallback callback = new SignInQueryCallback(request);
                frCB.handle(new Callback[] {callback});
                Map<String, String> signInQueryMap = callback.getSignInQueryParamMap();
                StringBuilder sbQuery = new StringBuilder();
                for (String key : signInQueryMap.keySet()) {
                    if (sbQuery.length() > 0) {
                        sbQuery.append("&");
                    }
                    sbQuery.append(key).append('=').
                    append(URLEncoder.encode(signInQueryMap.get(key), "UTF-8"));
                }
                signInQuery = sbQuery.toString();
               
            }
        }
        return signInQuery;
    }

    private String resolveFreshness(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object freshnessObj = ((FederationProtocol)config.getProtocol()).getFreshness();
        String freshness = null;
        if (freshnessObj != null) {
            if (freshnessObj instanceof String) {
                freshness = (String)freshnessObj;
            } else if (freshnessObj instanceof CallbackHandler) {
                CallbackHandler frCB = (CallbackHandler)freshnessObj;
                FreshnessCallback callback = new FreshnessCallback(request);
                frCB.handle(new Callback[] {callback});
                freshness = callback.getFreshness();
            }
        }
        return freshness;
    }

    private String resolveHomeRealm(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object homeRealmObj = ((FederationProtocol)config.getProtocol()).getHomeRealm();
        String homeRealm = null;
        if (homeRealmObj != null) {
            if (homeRealmObj instanceof String) {
                homeRealm = (String)homeRealmObj;
            } else if (homeRealmObj instanceof CallbackHandler) {
                CallbackHandler hrCB = (CallbackHandler)homeRealmObj;
                HomeRealmCallback callback = new HomeRealmCallback(request);
                hrCB.handle(new Callback[] {callback});
                homeRealm = callback.getHomeRealm();
            }
        }
        return homeRealm;
    }

    private String resolveAuthenticationType(HttpServletRequest request, FedizContext config)
        throws IOException, UnsupportedCallbackException {
        Object wAuthObj = ((FederationProtocol)config.getProtocol()).getAuthenticationType();
        String wAuth = null;
        if (wAuthObj != null) {
            if (wAuthObj instanceof String) {
                wAuth = (String)wAuthObj;
            } else if (wAuthObj instanceof CallbackHandler) {
                CallbackHandler wauthCB = (CallbackHandler)wAuthObj;
                WAuthCallback callback = new WAuthCallback(request);
                wauthCB.handle(new Callback[] {callback});
                wAuth = callback.getWauth();
            }  
        }
        return wAuth;
    }
    
    private String resolveRequest(HttpServletRequest request, FedizContext config)
        throws IOException, UnsupportedCallbackException {
        Object wReqObj = ((FederationProtocol)config.getProtocol()).getRequest();
        String wReq = null;
        if (wReqObj != null) {
            if (wReqObj instanceof String) {
                wReq = (String)wReqObj;
            } else if (wReqObj instanceof CallbackHandler) {
                CallbackHandler wauthCB = (CallbackHandler)wReqObj;
                WReqCallback callback = new WReqCallback(request);
                wauthCB.handle(new Callback[] {callback});
                wReq = callback.getWreq();
            }  
        }
        return wReq;
    }
*/
    private String resolveIssuer(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object issuerObj = config.getProtocol().getIssuer();
        String issuerURL = null;
        if (issuerObj instanceof String) {
            issuerURL = (String)issuerObj;
        } else if (issuerObj instanceof CallbackHandler) {
            CallbackHandler issuerCB = (CallbackHandler)issuerObj;
            IDPCallback callback = new IDPCallback(request);
            issuerCB.handle(new Callback[] {callback});
            issuerURL = callback.getIssuerUrl().toString();
        }
        return issuerURL;
    }
/*
    private String resolveWTRealm(HttpServletRequest request, FedizContext config) throws IOException,
        UnsupportedCallbackException {
        Object wtRealmObj = ((FederationProtocol)config.getProtocol()).getRealm();
        String wtRealm = null;
        if (wtRealmObj != null) {
            if (wtRealmObj instanceof String) {
                wtRealm = (String)wtRealmObj;
            } else if (wtRealmObj instanceof CallbackHandler) {
                CallbackHandler hrCB = (CallbackHandler)wtRealmObj;
                RealmCallback callback = new RealmCallback(request);
                hrCB.handle(new Callback[] {callback});
                wtRealm = callback.getRealm();
            }
        } else {
            wtRealm = extractFullContextPath(request); //default value
        }
        return wtRealm;
    }

*/
    private String extractFullContextPath(HttpServletRequest request) throws MalformedURLException {
        String result = null;
        String contextPath = request.getContextPath();
        String requestUrl = request.getRequestURL().toString();
        String requestPath = new URL(requestUrl).getPath();
        // Cut request path of request url and add context path if not ROOT
        if (requestPath != null && requestPath.length() > 0) {
            int lastIndex = requestUrl.lastIndexOf(requestPath);
            result = requestUrl.substring(0, lastIndex);
        } else {
            result = requestUrl;
        }
        if (contextPath != null && contextPath.length() > 0) {
            // contextPath contains starting slash
            result = result + contextPath + "/";
        } else {
            result = result + "/";
        }
        return result;
    }
    
}
