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
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.zip.DataFormatException;

import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
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
import org.apache.cxf.fediz.core.samlsso.SAMLProtocolResponseValidator;
import org.apache.cxf.fediz.core.samlsso.SAMLSSOResponseValidator;
import org.apache.cxf.fediz.core.samlsso.SSOValidatorResponse;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.WSConstants;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLProcessorImpl extends AbstractFedizProcessor {

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
    
    private RequestState processRelayState(
        String relayState, RequestState requestState
    ) throws ProcessingException {
        if (relayState.getBytes().length <= 0 || relayState.getBytes().length > 80) {
            LOG.error("Invalid RelayState");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        if (requestState == null) {
            LOG.error("Missing Request State");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        return requestState;
    }
    
    protected FedizResponse processSignInRequest(
            FedizRequest request, FedizContext config)
        throws ProcessingException {
        SAMLProtocol protocol = (SAMLProtocol)config.getProtocol();
        RequestState requestState = 
            processRelayState(request.getState(), request.getRequestState());
        
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
        validateSamlResponseProtocol((org.opensaml.saml2.core.Response)responseObject, config);
        
        SSOValidatorResponse ssoValidatorResponse = 
            validateSamlSSOResponse((org.opensaml.saml2.core.Response)responseObject, 
                                request.getRequest(), requestState, config);
        
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
        
        // Check whether token already used for signin
        Date expires = validatorResponse.getExpires();
        if (expires == null) {
            expires = ssoValidatorResponse.getSessionNotOnOrAfter();
        }
        testForReplayAttack(validatorResponse.getUniqueTokenId(), config, expires);
        
        FedizResponse fedResponse = new FedizResponse(
                validatorResponse.getUsername(), validatorResponse.getIssuer(),
                validatorResponse.getRoles(), validatorResponse.getClaims(),
                validatorResponse.getAudience(),
                validatorResponse.getCreated(),
                expires,
                token,
                validatorResponse.getUniqueTokenId());

        return fedResponse;
    }
    
    /**
     * Validate the received SAML Response as per the protocol
     * @throws ProcessingException 
     */
    protected void validateSamlResponseProtocol(
        org.opensaml.saml2.core.Response samlResponse,
        FedizContext config
    ) throws ProcessingException {
        try {
            SAMLProtocolResponseValidator protocolValidator = new SAMLProtocolResponseValidator();
            protocolValidator.validateSamlResponse(samlResponse, config);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
    }
    
    /**
     * Validate the received SAML Response as per the Web SSO profile
     * @throws ProcessingException 
     */
    protected SSOValidatorResponse validateSamlSSOResponse(
        org.opensaml.saml2.core.Response samlResponse,
        HttpServletRequest request,
        RequestState requestState,
        FedizContext config
    ) throws ProcessingException {
        try {
            SAMLSSOResponseValidator ssoResponseValidator = new SAMLSSOResponseValidator();
            String requestURL = request.getRequestURL().toString();
            ssoResponseValidator.setAssertionConsumerURL(requestURL);
            ssoResponseValidator.setClientAddress(request.getRemoteAddr());

            ssoResponseValidator.setIssuerIDP(requestState.getIdpServiceAddress());
            ssoResponseValidator.setRequestId(requestState.getRequestId());
            ssoResponseValidator.setSpIdentifier(requestState.getIssuerId());
            ssoResponseValidator.setEnforceAssertionsSigned(true);
            ssoResponseValidator.setEnforceKnownIssuer(true);
            ssoResponseValidator.setReplayCache(config.getTokenReplayCache());

            return ssoResponseValidator.validateSamlResponse(samlResponse, false);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
    }

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
            String realm = resolveWTRealm(request, config);
            AuthnRequest authnRequest = 
                authnRequestBuilder.createAuthnRequest(realm, requestURL);
            
            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                authnRequest.setDestination(redirectURL);
            }
            
            Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
            String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);
            
            String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
            RequestState requestState = new RequestState();
            requestState.setTargetAddress(requestURL);
            requestState.setIdpServiceAddress(redirectURL);
            requestState.setRequestId(authnRequest.getID());
            requestState.setIssuerId(realm);
            requestState.setWebAppContext(authnRequest.getIssuer().getValue());
            requestState.setState(relayState);
            requestState.setCreatedAt(System.currentTimeMillis());
            
            String urlEncodedRequest = 
                URLEncoder.encode(authnRequestEncoded, "UTF-8");
            
            StringBuilder sb = new StringBuilder();
            sb.append(SAMLSSOConstants.SAML_REQUEST).append('=').append(urlEncodedRequest);
            sb.append("&" + SAMLSSOConstants.RELAY_STATE).append('=').append(relayState);
            
            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                String signature = signRequest(config, sb);
                sb.append("&" + SAMLSSOConstants.SIGNATURE).append('=').append(signature);
            }
            
            RedirectionResponse response = new RedirectionResponse();
            response.addHeader("Cache-Control", "no-cache, no-store");
            response.addHeader("Pragma", "no-cache");
            response.setRequestState(requestState);
            
            redirectURL = redirectURL + "?" + sb.toString();
            response.setRedirectionURL(redirectURL);
            
            return response;
        } catch (Exception ex) {
            LOG.error("Failed to create SignInRequest", ex);
            throw new ProcessingException("Failed to create SignInRequest");
        }
    }
    
    /**
     * Sign a request according to the redirect binding spec for Web SSO
     */
    private String signRequest(
        FedizContext config,
        StringBuilder sb
    ) throws Exception {
        Crypto crypto = config.getSigningKey().getCrypto();
        if (crypto == null) {
            LOG.debug("No crypto instance of properties file configured for signature");
            throw new ProcessingException("Failed to Sign Request");
        }
        String signatureUser = config.getSigningKey().getKeyAlias();
        if (signatureUser == null) {
            LOG.debug("No user configured for signature");
            throw new ProcessingException("Failed to Sign Request");
        }
        String signaturePassword = config.getSigningKey().getKeyPassword();
        if (signaturePassword == null) {
            LOG.debug("No signature password available");
            throw new ProcessingException("Failed to Sign Request");
        }
        
        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey(signatureUser, signaturePassword);
        if (privateKey == null) {
            LOG.debug("No private key available");
            throw new ProcessingException("Failed to Sign Request");
        }
        
        String sigAlgo = WSConstants.RSA_SHA1;
        String jceSigAlgo = "SHA1withRSA";
        LOG.debug("automatic sig algo detection: " + privateKey.getAlgorithm());
        if (privateKey.getAlgorithm().equalsIgnoreCase("DSA")) {
            sigAlgo = WSConstants.DSA;
            jceSigAlgo = "SHA1withDSA";
        }
        LOG.debug("Using Signature algorithm " + sigAlgo);
        
        // Sign the request
        Signature signature = Signature.getInstance(jceSigAlgo);
        signature.initSign(privateKey);
       
        sb.append("&" + SAMLSSOConstants.SIG_ALG).append('=').append(URLEncoder.encode(sigAlgo, "UTF-8"));
        String requestToSign = sb.toString();

        signature.update(requestToSign.getBytes("UTF-8"));
        byte[] signBytes = signature.sign();
        
        String encodedSignature = Base64.encode(signBytes);
        
        return URLEncoder.encode(encodedSignature, "UTF-8");
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
    
}
