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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.zip.DataFormatException;

import javax.security.auth.DestroyFailedException;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.TokenValidatorRequest;
import org.apache.cxf.fediz.core.TokenValidatorResponse;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.KeyManager;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.metadata.MetadataWriter;
import org.apache.cxf.fediz.core.samlsso.CompressionUtils;
import org.apache.cxf.fediz.core.samlsso.SAMLPRequestBuilder;
import org.apache.cxf.fediz.core.samlsso.SAMLProtocolResponseValidator;
import org.apache.cxf.fediz.core.samlsso.SAMLSSOResponseValidator;
import org.apache.cxf.fediz.core.samlsso.SSOValidatorResponse;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.WSConstants;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
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

        if (request.getResponseToken() == null) {
            LOG.error("Missing response token parameter");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        if (request.isSignOutResponse()) {
            return processSignOutResponse(request, config);
        }

        if (request.getState() == null && config.isRequestStateValidation()) {
            LOG.error("Missing RelayState parameter");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        return processSignInRequest(request, config);
    }


    public Document getMetaData(HttpServletRequest request, FedizContext config) throws ProcessingException {
        return new MetadataWriter().getMetaData(request, config);
    }

    private RequestState processRelayState(
        String relayState, RequestState requestState, FedizContext config
    ) throws ProcessingException {
        if (config.isRequestStateValidation() 
            && (relayState.getBytes().length <= 0 || relayState.getBytes().length > 80)) {
            LOG.error("Invalid RelayState");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        return requestState;
    }

    protected FedizResponse processSignInRequest(FedizRequest request, FedizContext config) throws ProcessingException {
        
        SAMLProtocol protocol = (SAMLProtocol)config.getProtocol();
        RequestState requestState =
            processRelayState(request.getState(), request.getRequestState(), config);

        final XMLObject responseObject = getXMLObjectFromToken(request.getResponseToken(),
            protocol.isDisableDeflateEncoding());
        if (!(responseObject instanceof org.opensaml.saml.saml2.core.Response)) {
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        // Decrypt encrypted assertions
        decryptEncryptedAssertions((org.opensaml.saml.saml2.core.Response) responseObject, config);

        // Validate the Response
        validateSamlResponseProtocol((org.opensaml.saml.saml2.core.Response)responseObject, config);

        SSOValidatorResponse ssoValidatorResponse =
            validateSamlSSOResponse((org.opensaml.saml.saml2.core.Response)responseObject,
                                request.getRequest(), requestState, config);

        // Validate the internal assertion(s)
        TokenValidatorResponse validatorResponse = null;
        List<Assertion> assertions = ((org.opensaml.saml.saml2.core.Response)responseObject).getAssertions();

        if (assertions.isEmpty()) {
            LOG.debug("No Assertion extracted from SAML Response");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
        Element token = assertions.get(0).getDOM();

        List<TokenValidator> validators = protocol.getTokenValidators();
        for (TokenValidator validator : validators) {
            boolean canHandle = validator.canHandleToken(token);
            if (canHandle) {
                try {
                    TokenValidatorRequest validatorRequest =
                        new TokenValidatorRequest(token, request.getCerts());
                    boolean doNotEnforceAssertionsSigned =
                            ((SAMLProtocol)config.getProtocol()).isDoNotEnforceEncryptedAssertionsSigned()
                            && !((org.opensaml.saml.saml2.core.Response)responseObject).getEncryptedAssertions()
                            .isEmpty();
                    validatorRequest.setEnforceTokenSigned(!doNotEnforceAssertionsSigned);
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

        if (validatorResponse == null) {
            LOG.warn("No token validation response was available");
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }

        // Check whether token already used for signin
        Instant expires = validatorResponse.getExpires();
        if (expires == null) {
            expires = ssoValidatorResponse.getSessionNotOnOrAfter();
        }
        testForReplayAttack(validatorResponse.getUniqueTokenId(), config, expires);

        List<Claim> claims = validatorResponse.getClaims();

        testForMandatoryClaims(config.getProtocol().getRoleURI(),
                               config.getProtocol().getClaimTypesRequested(),
                               claims);

        if (config.getClaimsProcessor() != null) {
            List<ClaimsProcessor> processors = config.getClaimsProcessor();
            if (processors != null) {
                for (ClaimsProcessor cp : processors) {
                    LOG.debug("invoking ClaimsProcessor {}", cp);
                    claims = cp.processClaims(claims);
                }
            }
        }

        List<String> roles = getRoles(claims, config.getProtocol().getRoleURI());
        
        FedizResponse fedResponse = new FedizResponse(
                validatorResponse.getUsername(), validatorResponse.getIssuer(),
                roles, claims,
                validatorResponse.getAudience(),
                validatorResponse.getCreated(),
                expires,
                token,
                validatorResponse.getUniqueTokenId());

        return fedResponse;
    }

    private void decryptEncryptedAssertions(org.opensaml.saml.saml2.core.Response responseObject, FedizContext config)
            throws ProcessingException {
        if (responseObject.getEncryptedAssertions() != null && !responseObject.getEncryptedAssertions().isEmpty()) {
            KeyManager decryptionKeyManager = config.getDecryptionKey();
            if (decryptionKeyManager == null || decryptionKeyManager.getCrypto() == null) {
                LOG.debug("We must have a decryption Crypto instance configured to decrypt encrypted tokens");
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
            String keyPassword = decryptionKeyManager.getKeyPassword();
            if (keyPassword == null) {
                LOG.debug("We must have a decryption key password to decrypt encrypted tokens");
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
     
            String keyAlias = decryptionKeyManager.getKeyAlias();
            if (keyAlias == null) {
                LOG.debug("No alias configured for decrypt");
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
            
            try {
                // Get the private key
                PrivateKey privateKey = decryptionKeyManager.getCrypto().getPrivateKey(keyAlias, keyPassword);
                if (privateKey == null) {
                    LOG.debug("No private key available");
                    throw new ProcessingException(TYPE.BAD_REQUEST);
                }
                
                BasicX509Credential cred = new BasicX509Credential(
                    CertsUtils.getX509CertificateFromCrypto(decryptionKeyManager.getCrypto(), keyAlias));
                cred.setPrivateKey(privateKey);
                
                StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(cred);
                
                ChainingEncryptedKeyResolver keyResolver = new ChainingEncryptedKeyResolver(
                        Arrays.asList(
                                new InlineEncryptedKeyResolver(),
                                new EncryptedElementTypeEncryptedKeyResolver(), 
                                new SimpleRetrievalMethodEncryptedKeyResolver(),
                                new SimpleKeyInfoReferenceEncryptedKeyResolver()));
                
                Decrypter decrypter = new Decrypter(null, resolver, keyResolver);
                
                for (EncryptedAssertion encryptedAssertion : responseObject.getEncryptedAssertions()) {
                
                    Assertion decrypted = decrypter.decrypt(encryptedAssertion);
                    Element decryptedToken = decrypted.getDOM();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Decrypted assertion: {}", DOM2Writer.nodeToString(decryptedToken));
                    }
                    responseObject.getAssertions().add(decrypted);
                    // Add the decrypted Assertion to the Response DOM, as otherwise there's a problem with
                    // doc.getElementById() when trying to verify the signature of the decrypted assertion
                    decryptedToken.getOwnerDocument().getDocumentElement().appendChild(decryptedToken);
                }
            } catch (Exception e) {
                LOG.debug("Cannot decrypt assertions", e);
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
        }
    }

    private FedizResponse processSignOutResponse(FedizRequest request, FedizContext config) throws ProcessingException {
        SAMLProtocol protocol = (SAMLProtocol)config.getProtocol();

        final XMLObject responseObject = getXMLObjectFromToken(request.getResponseToken(),
            protocol.isDisableDeflateEncoding());
        if (!(responseObject instanceof org.opensaml.saml.saml2.core.LogoutResponse)) {
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        org.opensaml.saml.saml2.core.LogoutResponse logoutResponse =
            (org.opensaml.saml.saml2.core.LogoutResponse)responseObject;

        // Validate the Response
        validateSamlResponseProtocol(logoutResponse, config);

        // Enforce that the LogoutResponse is signed - we don't support a separate signature for now
        if (!logoutResponse.isSigned()) {
            LOG.debug("The LogoutResponse is not signed");
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        Instant issueInstant = logoutResponse.getIssueInstant().toDate().toInstant();

        FedizResponse fedResponse = new FedizResponse(
            null, logoutResponse.getIssuer().getValue(),
            Collections.emptyList(), Collections.emptyList(),
            null,
            issueInstant,
            null,
            null,
            logoutResponse.getID());

        return fedResponse;
    }

    private static XMLObject getXMLObjectFromToken(String token, boolean isDisableDeflateEncoding)
        throws ProcessingException {
        final InputStream tokenStream;
        try {
            byte[] deflatedToken = Base64.getDecoder().decode(token);
            if (isDisableDeflateEncoding) {
                tokenStream = new ByteArrayInputStream(deflatedToken);
            } else {
                tokenStream = CompressionUtils.inflate(deflatedToken);
            }
        } catch (IllegalArgumentException | DataFormatException ex) {
            LOG.warn("Invalid data format", ex);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        final Element el;
        try (InputStream is = tokenStream) {
            el = DOMUtils.readXml(is).getDocumentElement();
        } catch (Exception e) {
            LOG.warn("Failed to parse token", e);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received response: " + DOM2Writer.nodeToString(el));
        }

        try {
            return OpenSAMLUtil.fromDom(el);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw new ProcessingException(TYPE.INVALID_REQUEST);
        }
    }

    /**
     * Validate the received SAML Response as per the protocol
     * @throws ProcessingException
     */
    protected void validateSamlResponseProtocol(
        StatusResponseType samlResponse,
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
        org.opensaml.saml.saml2.core.Response samlResponse,
        HttpServletRequest request,
        RequestState requestState,
        FedizContext config
    ) throws ProcessingException {
        try {
            SAMLSSOResponseValidator ssoResponseValidator = new SAMLSSOResponseValidator();
            String requestURL = request.getRequestURL().toString();
            ssoResponseValidator.setAssertionConsumerURL(requestURL);
            boolean disableClientAddressCheck = ((SAMLProtocol)config.getProtocol()).isDisableClientAddressCheck();
            if (!disableClientAddressCheck) {
                ssoResponseValidator.setClientAddress(request.getRemoteAddr());
            }

            boolean doNotEnforceKnownIssuer =
                ((SAMLProtocol)config.getProtocol()).isDoNotEnforceKnownIssuer();
            ssoResponseValidator.setEnforceKnownIssuer(!doNotEnforceKnownIssuer);

            ssoResponseValidator.setIssuerIDP(requestState != null ? requestState.getIdpServiceAddress() : null);
            ssoResponseValidator.setRequestId(requestState != null ? requestState.getRequestId() : null);
            ssoResponseValidator.setSpIdentifier(requestState != null ? requestState.getIssuerId() : null);
            
            boolean doNotEnforceAssertionsSigned =
                    ((SAMLProtocol)config.getProtocol()).isDoNotEnforceEncryptedAssertionsSigned()
                    && !samlResponse.getEncryptedAssertions().isEmpty();
            ssoResponseValidator.setEnforceAssertionsSigned(!doNotEnforceAssertionsSigned);
            
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

        try {
            if (!(config.getProtocol() instanceof SAMLProtocol)) {
                LOG.error("Unsupported protocol");
                throw new IllegalStateException("Unsupported protocol");
            }

            String redirectURL = null;
            String issuerURL = resolveIssuer(request, config);
            LOG.info("Issuer url: " + issuerURL);
            if (issuerURL != null && !issuerURL.isEmpty()) {
                redirectURL = issuerURL;
            }

            SAMLPRequestBuilder samlpRequestBuilder =
                ((SAMLProtocol)config.getProtocol()).getSAMLPRequestBuilder();

            Document doc = DOMUtils.createDocument();
            doc.appendChild(doc.createElement("root"));

            // Create the AuthnRequest
            String reply = resolveReply(request, config);
            if (reply == null || reply.isEmpty()) {
                reply = request.getRequestURL().toString();
            } else {
                try {
                    new URL(reply);
                } catch (MalformedURLException ex) {
                    if (reply.startsWith("/")) {
                        reply = extractFullContextPath(request).concat(reply.substring(1));
                    } else {
                        reply = extractFullContextPath(request).concat(reply);
                    }
                }
            }
            String realm = resolveWTRealm(request, config);
            AuthnRequest authnRequest =
                samlpRequestBuilder.createAuthnRequest(realm, reply);

            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                authnRequest.setDestination(redirectURL);
            }

            Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
            String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);

            String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
            RequestState requestState = new RequestState();
            requestState.setTargetAddress(reply);
            requestState.setIdpServiceAddress(redirectURL);
            requestState.setRequestId(authnRequest.getID());
            requestState.setIssuerId(realm);
            requestState.setWebAppContext(authnRequest.getIssuer().getValue());
            requestState.setState(relayState);
            requestState.setCreatedAt(System.currentTimeMillis());

            String urlEncodedRequest =
                URLEncoder.encode(authnRequestEncoded, "UTF-8");

            String signInQuery = resolveSignInQuery(request, config);

            StringBuilder sb = new StringBuilder(SAMLSSOConstants.SAML_REQUEST).append('=').append(urlEncodedRequest)
                .append('&').append(SAMLSSOConstants.RELAY_STATE).append('=').append(relayState);

            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                String signature = signRequest(config, sb);
                sb.append('&').append(SAMLSSOConstants.SIGNATURE).append('=').append(signature);
            }

            // add signin query extensions
            if (signInQuery != null && signInQuery.length() > 0) {
                sb.append('&').append(signInQuery);
            }

            RedirectionResponse response = new RedirectionResponse();
            response.addHeader("Cache-Control", "no-cache, no-store");
            response.addHeader("Pragma", "no-cache");
            response.setRequestState(requestState);

            response.setRedirectionURL(redirectURL + '?' + sb.toString());

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
        if ("DSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            sigAlgo = WSConstants.DSA;
            jceSigAlgo = "SHA1withDSA";
        } else {
            switch(((SAMLProtocol)config.getProtocol()).getSignRequestAlgorithm()) {
            case RSA_SHA1:
                sigAlgo = WSConstants.RSA_SHA1;
                jceSigAlgo = "SHA1withRSA";
                break;
            case RSA_SHA256:
                sigAlgo = WSConstants.RSA_SHA256;
                jceSigAlgo = "SHA256withRSA";
                break;
            default:
                throw new ProcessingException("Unknown sign algorithm");
            }
        }
        LOG.debug("Using Signature algorithm " + sigAlgo);

        // Sign the request
        Signature signature = Signature.getInstance(jceSigAlgo);
        signature.initSign(privateKey);

        sb.append('&').append(SAMLSSOConstants.SIG_ALG).append('=').append(URLEncoder.encode(sigAlgo, "UTF-8"));
        String requestToSign = sb.toString();

        signature.update(requestToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);
        
        // Clean the private key from memory when we're done
        try {
            privateKey.destroy();
        } catch (DestroyFailedException ex) {
            // ignore
        }

        return URLEncoder.encode(encodedSignature, "UTF-8");
    }

    protected String encodeAuthnRequest(Element authnRequest) {
        String requestMessage = DOM2Writer.nodeToString(authnRequest);

        byte[] deflatedBytes = CompressionUtils.deflate(requestMessage.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(deflatedBytes);
    }

    @Override
    public RedirectionResponse createSignOutRequest(HttpServletRequest request,
                                                    SamlAssertionWrapper token,
                                                    FedizContext config)
        throws ProcessingException {

        try {
            if (!(config.getProtocol() instanceof SAMLProtocol)) {
                LOG.error("Unsupported protocol");
                throw new IllegalStateException("Unsupported protocol");
            }

            String redirectURL = ((SAMLProtocol)config.getProtocol()).getIssuerLogoutURL();
            if (redirectURL == null) {
                String issuerURL = resolveIssuer(request, config);
                LOG.info("Issuer url: " + issuerURL);
                if (issuerURL != null && !issuerURL.isEmpty()) {
                    redirectURL = issuerURL;
                }
            }
            if (redirectURL == null) {
                LOG.debug("No issuerLogoutURL or issuer parameter specified for logout");
                throw new ProcessingException("Failed to create SignOutRequest");
            }

            SAMLPRequestBuilder samlpRequestBuilder =
                ((SAMLProtocol)config.getProtocol()).getSAMLPRequestBuilder();

            Document doc = DOMUtils.createDocument();
            doc.appendChild(doc.createElement("root"));

            // Create the LogoutRequest
            String realm = resolveWTRealm(request, config);
            String reason = "urn:oasis:names:tc:SAML:2.0:logout:user";
            LogoutRequest logoutRequest =
                samlpRequestBuilder.createLogoutRequest(realm, reason, token);

            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                logoutRequest.setDestination(redirectURL);
            }

            Element logoutRequestElement = OpenSAMLUtil.toDom(logoutRequest, doc);
            String logoutRequestEncoded = encodeAuthnRequest(logoutRequestElement);

            String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

            String urlEncodedRequest =
                URLEncoder.encode(logoutRequestEncoded, "UTF-8");

            StringBuilder sb = new StringBuilder(SAMLSSOConstants.SAML_REQUEST).append('=').append(urlEncodedRequest)
                .append('&').append(SAMLSSOConstants.RELAY_STATE).append('=').append(relayState);

            if (((SAMLProtocol)config.getProtocol()).isSignRequest()) {
                String signature = signRequest(config, sb);
                sb.append('&').append(SAMLSSOConstants.SIGNATURE).append('=').append(signature);
            }

            RedirectionResponse response = new RedirectionResponse();
            response.addHeader("Cache-Control", "no-cache, no-store");
            response.addHeader("Pragma", "no-cache");
            response.setState(relayState);

            response.setRedirectionURL(redirectURL + '?' + sb.toString());

            return response;
        } catch (Exception ex) {
            LOG.error("Failed to create SignOutRequest", ex);
            throw new ProcessingException("Failed to create SignOutRequest");
        }
    }

}
