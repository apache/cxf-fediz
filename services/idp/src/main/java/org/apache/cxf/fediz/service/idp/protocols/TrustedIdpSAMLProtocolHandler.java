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
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.UUID;
import java.util.zip.DataFormatException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.UriBuilder;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Exception;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.spi.TrustedIdpProtocolHandler;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.jaxrs.utils.ExceptionUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.cxf.rs.security.saml.sso.AuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.DefaultAuthnRequestBuilder;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

@Component
public class TrustedIdpSAMLProtocolHandler implements TrustedIdpProtocolHandler {

    public static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpSAMLProtocolHandler.class);

    private AuthnRequestBuilder authnRequestBuilder = new DefaultAuthnRequestBuilder();
    // private long stateTimeToLive = SSOConstants.DEFAULT_STATE_TIME;

    static {
        OpenSAMLUtil.initSamlEngine();
    }

    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        // TODO Auto-generated method stub
        return false;
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
            // if (isSignRequest()) {
            //    authnRequest.setDestination(idpServiceAddress);
            //}
            Element authnRequestElement = OpenSAMLUtil.toDom(authnRequest, doc);
            String authnRequestEncoded = encodeAuthnRequest(authnRequestElement);

            String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

            String urlEncodedRequest = URLEncoder.encode(authnRequestEncoded, "UTF-8");

            UriBuilder ub = UriBuilder.fromUri(trustedIdp.getUrl());

            ub.queryParam(SSOConstants.SAML_REQUEST, urlEncodedRequest);
            ub.queryParam(SSOConstants.RELAY_STATE, relayState);
            //if (isSignRequest()) {
            //    signRequest(urlEncodedRequest, info.getRelayState(), ub);
            //}

            /*context.abortWith(Response.seeOther(ub.build())
                           .header(HttpHeaders.CACHE_CONTROL, "no-cache, no-store")
                           .header("Pragma", "no-cache") 
                           .build());*/

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


    protected String encodeAuthnRequest(Element authnRequest) throws IOException {
        String requestMessage = DOM2Writer.nodeToString(authnRequest);

        DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
        byte[] deflatedBytes = encoder.deflateToken(requestMessage.getBytes("UTF-8"));

        return Base64Utility.encode(deflatedBytes);
    }

    @Override
    public SecurityToken mapSignInResponse(RequestContext context, Idp idp, TrustedIdp trustedIdp) {

        try {
            String relayState = (String) WebUtils.getAttributeFromFlowScope(context,
                                                                            SSOConstants.RELAY_STATE);
            // TODO Validate RelayState
            System.out.println("RS: " + relayState);

            String encodedSAMLResponse = (String) WebUtils.getAttributeFromFlowScope(context, 
                                                                                     SSOConstants.SAML_RESPONSE);
            org.opensaml.saml2.core.Response samlResponse = 
                readSAMLResponse(false, encodedSAMLResponse);

            // Validate the Response
            /*
             * TODOvalidateSamlResponseProtocol(samlResponse);
            SSOValidatorResponse validatorResponse = 
                validateSamlSSOResponse(false, samlResponse, requestState);

            String assertion = validatorResponse.getAssertion();
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(assertion);
            */
            SamlAssertionWrapper wrapper = 
                new SamlAssertionWrapper(samlResponse.getAssertions().get(0));

            // Create new Security token with new id. 
            // Parameters for freshness computation are copied from original IDP_TOKEN
            String id = IDGenerator.generateID("_");
            SecurityToken idpToken = new SecurityToken(id);
                // new SecurityToken(id, new Date(), validatorResponse.getSessionNotOnOrAfter());
            // TODO new Date() above incorrect

            idpToken.setToken(wrapper.toDOM(DOMUtils.newDocument()));
            // LOG.info("[IDP_TOKEN={}] for user '{}' created from [RP_TOKEN={}] issued by home realm [{}/{}]",
            //         id, wfResp.getUsername(), wfResp.getUniqueTokenId(), whr, wfResp.getIssuer());
            //.debug("Created date={}", wfResp.getTokenCreated());
            //LOG.debug("Expired date={}", wfResp.getTokenExpires());
            //if (LOG.isDebugEnabled()) {
            //    LOG.debug("Validated 'wresult' : "
            //        + System.getProperty("line.separator") + wresult);
            //}
            return idpToken;
        } catch (IllegalStateException ex) {
            throw ex;
        } catch (Exception ex) {
            LOG.warn("Unexpected exception occured", ex);
            throw new IllegalStateException("Unexpected exception occured: " + ex.getMessage());
        }
    }

    private org.opensaml.saml2.core.Response readSAMLResponse(
        boolean postBinding, String samlResponse
    ) {
        if (StringUtils.isEmpty(samlResponse)) {
            throw ExceptionUtils.toBadRequestException(null, null);
        }

        String samlResponseDecoded = samlResponse;
        /*
            // URL Decoding only applies for the re-direct binding
            if (!postBinding) {
            try {
                samlResponseDecoded = URLDecoder.decode(samlResponse, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    throw ExceptionUtils.toBadRequestException(null, null);
                }
            }
         */
        InputStream tokenStream = null;
        // (isSupportBase64Encoding()) { TODO
        try {
            byte[] deflatedToken = Base64Utility.decode(samlResponseDecoded);
            tokenStream = !postBinding //&& isSupportDeflateEncoding() 
                ? new DeflateEncoderDecoder().inflateToken(deflatedToken)
                    : new ByteArrayInputStream(deflatedToken); 
        } catch (Base64Exception ex) {
            throw ExceptionUtils.toBadRequestException(ex, null);
        } catch (DataFormatException ex) {
            throw ExceptionUtils.toBadRequestException(ex, null);
        }
        /*} else { TODO
            try {
                tokenStream = new ByteArrayInputStream(samlResponseDecoded.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                throw ExceptionUtils.toBadRequestException(ex, null);
            }
        }*/

        Document responseDoc = null;
        try {
            responseDoc = StaxUtils.read(new InputStreamReader(tokenStream, "UTF-8"));
        } catch (Exception ex) {
            throw new WebApplicationException(400);
        }

        LOG.debug("Received response: " + DOM2Writer.nodeToString(responseDoc.getDocumentElement()));

        XMLObject responseObject = null;
        try {
            responseObject = OpenSAMLUtil.fromDom(responseDoc.getDocumentElement());
        } catch (WSSecurityException ex) {
            throw ExceptionUtils.toBadRequestException(ex, null);
        }
        if (!(responseObject instanceof org.opensaml.saml2.core.Response)) {
            throw ExceptionUtils.toBadRequestException(null, null);
        }
        return (org.opensaml.saml2.core.Response)responseObject;
    }

    /**
     * Validate the received SAML Response as per the protocol
    protected void validateSamlResponseProtocol(
        org.opensaml.saml2.core.Response samlResponse
    ) {
        try {
            SAMLProtocolResponseValidator protocolValidator = new SAMLProtocolResponseValidator();
            protocolValidator.setKeyInfoMustBeAvailable(true); // TODO
            protocolValidator.validateSamlResponse(samlResponse, getSignatureCrypto(), null);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw ExceptionUtils.toBadRequestException(null, null);
        }
    }
    */
    /**
     * Validate the received SAML Response as per the Web SSO profile
    protected SSOValidatorResponse validateSamlSSOResponse(
        boolean postBinding,
        org.opensaml.saml2.core.Response samlResponse,
        Idp idp, 
        TrustedIdp trustedIdp
    ) {
        try {
            SAMLSSOResponseValidator ssoResponseValidator = new SAMLSSOResponseValidator();
            ssoResponseValidator.setAssertionConsumerURL(idp.getIdpUrl());

            // ssoResponseValidator.setClientAddress(client_ip);

            ssoResponseValidator.setIssuerIDP(trustedIdp.getUrl());
            // ssoResponseValidator.setRequestId(requestState.getSamlRequestId());
            ssoResponseValidator.setSpIdentifier(idp.getRealm());
            ssoResponseValidator.setEnforceAssertionsSigned(true); // TODO
            // ssoResponseValidator.setEnforceKnownIssuer(enforceKnownIssuer);

            return ssoResponseValidator.validateSamlResponse(samlResponse, postBinding);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            throw ExceptionUtils.toBadRequestException(ex, null);
        }
    }
    */

/*
    private FedizContext getFedizContext(Idp idpConfig,
                                         TrustedIdp trustedIdpConfig) throws ProcessingException {

        ContextConfig config = new ContextConfig();

        config.setName("whatever");

        // Configure certificate store
        String certificate = trustedIdpConfig.getCertificate();
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            CertificateStores certStores = new CertificateStores();
            TrustManagersType tm0 = new TrustManagersType();
            KeyStoreType ks0 = new KeyStoreType();
            ks0.setType("PEM");
            // ks0.setType("JKS");
            // ks0.setPassword("changeit");
            ks0.setFile(trustedIdpConfig.getCertificate());
            tm0.setKeyStore(ks0);
            certStores.getTrustManager().add(tm0);
            config.setCertificateStores(certStores);
        }

        // Configure trusted IDP
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        TrustedIssuerType ti0 = new TrustedIssuerType();
        ti0.setCertificateValidation(ValidationType.PEER_TRUST);
        ti0.setName(trustedIdpConfig.getName());
        // ti0.setSubject(".*CN=www.sts.com.*");
        trustedIssuers.getIssuer().add(ti0);
        config.setTrustedIssuers(trustedIssuers);

        FederationProtocolType protocol = new FederationProtocolType();
        config.setProtocol(protocol);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(idpConfig.getRealm());
        config.setAudienceUris(audienceUris);

        FedizContext fedContext = new FedizContext(config);
        if (!isCertificateLocation) {
            CertificateStore cs = null;

            X509Certificate cert;
            try {
                cert = parseCertificate(trustedIdpConfig.getCertificate());
            } catch (Exception ex) {
                LOG.error("Failed to parse trusted certificate", ex);
                throw new ProcessingException("Failed to parse trusted certificate");
            }
            cs = new CertificateStore(Collections.singletonList(cert).toArray(new X509Certificate[0]));

            TrustManager tm = new TrustManager(cs);
            fedContext.getCertificateStores().add(tm);
        }

        fedContext.init();
        return fedContext;
    }

    private X509Certificate parseCertificate(String certificate)
        throws CertificateException, Base64DecodingException {

        //before decoding we need to get rod off the prefix and suffix
        byte [] decoded = Base64.decode(certificate.replaceAll("-----BEGIN CERTIFICATE-----", "").
                                        replaceAll("-----END CERTIFICATE-----", ""));

        return (X509Certificate)CertificateFactory.getInstance("X.509").
            generateCertificate(new ByteArrayInputStream(decoded));
    }
*/

}
