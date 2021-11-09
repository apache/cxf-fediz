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

package org.apache.cxf.fediz.service.idp.protocols;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.zip.DataFormatException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.UriBuilder;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Exception;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.jaxrs.utils.ExceptionUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.rs.security.saml.sso.AuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.DefaultAuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.EHCacheTokenReplayCache;
import org.apache.cxf.rs.security.saml.sso.SAMLProtocolResponseValidator;
import org.apache.cxf.rs.security.saml.sso.SAMLSSOResponseValidator;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.cxf.rs.security.saml.sso.SSOValidatorResponse;
import org.apache.cxf.rs.security.saml.sso.TokenReplayCache;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

@Component
public class TrustedIdpSAMLProtocolHandler extends AbstractTrustedIdpProtocolHandler {
    /**
     * Whether to sign the request or not. The default is "true".
     */
    public static final String SIGN_REQUEST = "sign.request";

    /**
     * Whether to require a KeyInfo or not when processing a (signed) Response. The default is "true".
     */
    public static final String REQUIRE_KEYINFO = "require.keyinfo";

    /**
     * Whether the assertions contained in the Response must be signed or not (if the response itself
     * is not signed). The default is "true".
     */
    public static final String REQUIRE_SIGNED_ASSERTIONS = "require.signed.assertions";

    /**
     * Whether we have to "know" the issuer of the SAML Response or not. The default is "true".
     */
    public static final String REQUIRE_KNOWN_ISSUER = "require.known.issuer";

    /**
     * Whether we BASE-64 decode the response or not. The default is "true".
     */
    public static final String SUPPORT_BASE64_ENCODING = "support.base64.encoding";

    /**
     * Whether we support Deflate encoding or not. The default is "false".
     */
    public static final String SUPPORT_DEFLATE_ENCODING = "support.deflate.encoding";

    public static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpSAMLProtocolHandler.class);
    private static final String SAML_SSO_REQUEST_ID = "saml-sso-request-id";

    private AuthnRequestBuilder authnRequestBuilder = new DefaultAuthnRequestBuilder();
    private TokenReplayCache<String> replayCache;

    static {
        OpenSAMLUtil.initSamlEngine();
    }

    @Override
    public String getProtocol() {
        return PROTOCOL;
    }

    @Override
    public URL mapSignInRequest(RequestContext context, Idp idp, TrustedIdp trustedIdp) {

        try {
            Document doc = DOMUtils.createDocument();
            doc.appendChild(doc.createElement("root"));
            // Create the AuthnRequest
            AuthnRequest authnRequest =
                authnRequestBuilder.createAuthnRequest(
                    null, idp.getRealm(), idp.getIdpUrl().toString()
                );

            boolean signRequest = isBooleanPropertyConfigured(trustedIdp, SIGN_REQUEST, true);
            if (signRequest) {
                authnRequest.setDestination(trustedIdp.getUrl());
            }
            Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
            String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);

            String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, "UTF-8");

            UriBuilder ub = UriBuilder.fromUri(trustedIdp.getUrl());

            ub.queryParam(SSOConstants.SAML_REQUEST, urlEncodedRequest);

            String wctx = context.getFlowScope().getString(IdpConstants.TRUSTED_IDP_CONTEXT);
            ub.queryParam(SSOConstants.RELAY_STATE, wctx);
            if (signRequest) {
                signRequest(urlEncodedRequest, wctx, idp, ub);
            }

            // Store the Request ID
            String authnRequestId = authnRequest.getID();
            WebUtils.putAttributeInExternalContext(context, SAML_SSO_REQUEST_ID, authnRequestId);

            HttpServletResponse response = WebUtils.getHttpServletResponse(context);
            response.addHeader("Cache-Control", "no-cache, no-store");
            response.addHeader("Pragma", "no-cache");

            return ub.build().toURL();
        } catch (MalformedURLException ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        } catch (UnsupportedEncodingException ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        } catch (Exception ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        }
    }

    @Override
    public SecurityToken mapSignInResponse(RequestContext context, Idp idp, TrustedIdp trustedIdp) {

        try {
            String encodedSAMLResponse = (String) WebUtils.getAttributeFromFlowScope(context,
                                                                                     SSOConstants.SAML_RESPONSE);

            // Read the response + convert to an OpenSAML Response Object
            org.opensaml.saml.saml2.core.Response samlResponse =
                readSAMLResponse(encodedSAMLResponse, trustedIdp);

            Crypto crypto = CertsUtils.getCryptoFromCertificate(trustedIdp.getCertificate());
            validateSamlResponseProtocol(samlResponse, crypto, trustedIdp);
            // Validate the Response
            SSOValidatorResponse validatorResponse =
                validateSamlSSOResponse(samlResponse, idp, trustedIdp, context);

            // Create new Security token with new id.
            // Parameters for freshness computation are copied from original IDP_TOKEN
            String id = IDGenerator.generateID("_");
            SecurityToken idpToken =
                new SecurityToken(id, validatorResponse.getCreated(), validatorResponse.getSessionNotOnOrAfter());

            idpToken.setToken(validatorResponse.getAssertionElement());
            String whr = (String) WebUtils.getAttributeFromFlowScope(context, IdpConstants.HOME_REALM);
            LOG.info("[IDP_TOKEN={}] created from [RP_TOKEN={}] issued by home realm [{}]",
                     id, validatorResponse.getResponseId(), whr);
            LOG.debug("Created date={}", validatorResponse.getCreated());
            LOG.debug("Expired date={}", validatorResponse.getSessionNotOnOrAfter());
            LOG.debug("Validated: {}{}", System.getProperty("line.separator"), validatorResponse.getAssertion());
            return idpToken;
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            LOG.warn("Unexpected exception occured", ex);
            throw new IllegalStateException("Unexpected exception occured: " + ex.getMessage());
        }
    }

    private String encodeAuthnRequest(Element authnRequest) throws IOException {
        String requestMessage = DOM2Writer.nodeToString(authnRequest);

        LOG.debug(requestMessage);

        DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
        byte[] deflatedBytes = encoder.deflateToken(requestMessage.getBytes(StandardCharsets.UTF_8));

        return Base64Utility.encode(deflatedBytes);
    }

    /**
     * Sign a request according to the redirect binding spec for Web SSO
     */
    private void signRequest(
        String authnRequest,
        String relayState,
        Idp config,
        UriBuilder ub
    ) throws Exception {
        Crypto crypto = CertsUtils.getCryptoFromCertificate(config.getCertificate());
        if (crypto == null) {
            LOG.error("No crypto instance of properties file configured for signature");
            throw new IllegalStateException("Invalid IdP configuration");
        }

        String alias = crypto.getDefaultX509Identifier();
        X509Certificate cert = CertsUtils.getX509CertificateFromCrypto(crypto, alias);
        if (cert == null) {
            LOG.error("No cert was found to sign the request using alias: " + alias);
            throw new IllegalStateException("Invalid IdP configuration");
        }

        String sigAlgo = SSOConstants.RSA_SHA1;
        String pubKeyAlgo = cert.getPublicKey().getAlgorithm();
        String jceSigAlgo = "SHA1withRSA";
        LOG.debug("automatic sig algo detection: " + pubKeyAlgo);
        if ("DSA".equalsIgnoreCase(pubKeyAlgo)) {
            sigAlgo = SSOConstants.DSA_SHA1;
            jceSigAlgo = "SHA1withDSA";
        }
        LOG.debug("Using Signature algorithm " + sigAlgo);

        ub.queryParam(SSOConstants.SIG_ALG, URLEncoder.encode(sigAlgo, "UTF-8"));

        // Get the password
        String password = config.getCertificatePassword();

        // Get the private key
        PrivateKey privateKey = crypto.getPrivateKey(alias, password);

        // Sign the request
        Signature signature = Signature.getInstance(jceSigAlgo);
        signature.initSign(privateKey);

        String requestToSign =
            SSOConstants.SAML_REQUEST + "=" + authnRequest + "&"
            + SSOConstants.RELAY_STATE + "=" + relayState + "&"
            + SSOConstants.SIG_ALG + "=" + URLEncoder.encode(sigAlgo, "UTF-8");

        signature.update(requestToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = signature.sign();

        String encodedSignature = Base64.getEncoder().encodeToString(signBytes);

        ub.queryParam(SSOConstants.SIGNATURE, URLEncoder.encode(encodedSignature, "UTF-8"));
    }

    private org.opensaml.saml.saml2.core.Response readSAMLResponse(String samlResponse, TrustedIdp trustedIdp) {
        if (StringUtils.isEmpty(samlResponse)) {
            throw ExceptionUtils.toBadRequestException(null, null);
        }

        String samlResponseDecoded = samlResponse;

        final Reader reader;
        if (isBooleanPropertyConfigured(trustedIdp, SUPPORT_BASE64_ENCODING, true)) {
            try {
                byte[] deflatedToken = Base64Utility.decode(samlResponseDecoded);
                final InputStream tokenStream = isBooleanPropertyConfigured(trustedIdp, SUPPORT_DEFLATE_ENCODING, false)
                    ? new DeflateEncoderDecoder().inflateToken(deflatedToken)
                    : new ByteArrayInputStream(deflatedToken);
                reader = new InputStreamReader(tokenStream, StandardCharsets.UTF_8);
            } catch (Base64Exception | DataFormatException ex) {
                throw ExceptionUtils.toBadRequestException(ex, null);
            }
        } else {
            reader = new StringReader(samlResponseDecoded);
        }

        final Document responseDoc;
        try {
            responseDoc = StaxUtils.read(reader);
        } catch (Exception ex) {
            throw new WebApplicationException(400);
        }

        LOG.debug("Received response: " + DOM2Writer.nodeToString(responseDoc.getDocumentElement()));

        final XMLObject responseObject;
        try {
            responseObject = OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        } catch (WSSecurityException ex) {
            throw ExceptionUtils.toBadRequestException(ex, null);
        }
        if (!(responseObject instanceof org.opensaml.saml.saml2.core.Response)) {
            throw ExceptionUtils.toBadRequestException(null, null);
        }
        return (org.opensaml.saml.saml2.core.Response)responseObject;

    }

    /**
     * Validate the received SAML Response as per the protocol
     */
    private void validateSamlResponseProtocol(
        org.opensaml.saml.saml2.core.Response samlResponse, Crypto crypto, TrustedIdp trustedIdp
    ) {
        try {
            SAMLProtocolResponseValidator protocolValidator = new SAMLProtocolResponseValidator();
            protocolValidator.setKeyInfoMustBeAvailable(
                isBooleanPropertyConfigured(trustedIdp, REQUIRE_KEYINFO, true));
            protocolValidator.validateSamlResponse(samlResponse, crypto, null);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw ExceptionUtils.toBadRequestException(null, null);
        }
    }

    /**
     * Validate the received SAML Response as per the Web SSO profile
     */
    private SSOValidatorResponse validateSamlSSOResponse(
        org.opensaml.saml.saml2.core.Response samlResponse,
        Idp idp,
        TrustedIdp trustedIdp,
        RequestContext requestContext
    ) {
        try {
            SAMLSSOResponseValidator ssoResponseValidator = new SAMLSSOResponseValidator();
            ssoResponseValidator.setAssertionConsumerURL(idp.getIdpUrl().toString());

            HttpServletRequest servletRequest = WebUtils.getHttpServletRequest(requestContext);
            ssoResponseValidator.setClientAddress(servletRequest.getRemoteAddr());

            String issuer = trustedIdp.getIssuer();
            if (issuer == null || issuer.isEmpty()) {
                LOG.debug("Issuer name is not defined in trusted 3rd party configuration. "
                    + "Using URL instead for issuer validation");
                issuer = trustedIdp.getUrl();
            }
            LOG.debug("Using {} for issuer validation", issuer);
            ssoResponseValidator.setIssuerIDP(issuer);

            // Get the stored request ID
            String requestId =
                (String)WebUtils.getAttributeFromExternalContext(requestContext, SAML_SSO_REQUEST_ID);
            ssoResponseValidator.setRequestId(requestId);
            ssoResponseValidator.setSpIdentifier(idp.getRealm());
            ssoResponseValidator.setEnforceAssertionsSigned(
                isBooleanPropertyConfigured(trustedIdp, REQUIRE_SIGNED_ASSERTIONS, true));
            ssoResponseValidator.setEnforceKnownIssuer(
                isBooleanPropertyConfigured(trustedIdp, REQUIRE_KNOWN_ISSUER, true));

            HttpServletRequest httpServletRequest = WebUtils.getHttpServletRequest(requestContext);
            boolean post = "POST".equals(httpServletRequest.getMethod());
            if (post) {
                ssoResponseValidator.setReplayCache(getReplayCache());
            }

            return ssoResponseValidator.validateSamlResponse(samlResponse, post);
        } catch (Exception ex) {
            LOG.debug(ex.getMessage(), ex);
            throw ExceptionUtils.toBadRequestException(ex, null);
        }
    }

    public void setReplayCache(TokenReplayCache<String> replayCache) {
        this.replayCache = replayCache;
    }

    public TokenReplayCache<String> getReplayCache() throws IllegalAccessException, ReflectiveOperationException {
        if (replayCache == null) {
            replayCache = new EHCacheTokenReplayCache();
        }
        return replayCache;
    }
}
