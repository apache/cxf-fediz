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

package org.apache.cxf.fediz.core.samlsso;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;

import javax.security.auth.callback.CallbackHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.handler.LogoutHandler;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.easymock.EasyMock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

/**
 * Some tests for logout for SAML SSO
 */
public class SAMLLogoutTest {
    static final String TEST_REQUEST_URL = "https://localhost/fedizhelloworld/";
    static final String TEST_IDP_ISSUER = "http://url_to_the_issuer";
    static final String TEST_CLIENT_ADDRESS = "https://127.0.0.1";
    private static final String LOGOUT_URL = "https://localhost/fedizhelloworld/secure/logout";
    private static final String LOGOUT_URI = "/secure/logout";

    private static final String CONFIG_FILE = "fediz_test_config_saml.xml";

    private static Crypto crypto;
    private static CallbackHandler cbPasswordHandler;
    private static FedizConfigurator configurator;
    private static DocumentBuilderFactory docBuilderFactory;

    static {
        OpenSAMLUtil.initSamlEngine();
        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
    }


    @BeforeAll
    public static void init() {
        try {
            crypto = CryptoFactory.getInstance("signature.properties");
            cbPasswordHandler = new KeystoreCallbackHandler();
            getFederationConfigurator();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assertions.assertNotNull(configurator);
    }

    @AfterAll
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }


    private static FedizConfigurator getFederationConfigurator() {
        if (configurator != null) {
            return configurator;
        }
        try {
            configurator = new FedizConfigurator();
            final URL resource = Thread.currentThread().getContextClassLoader()
                    .getResource(CONFIG_FILE);
            File f = new File(resource.toURI());
            configurator.loadConfig(f);
            return configurator;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @org.junit.jupiter.api.Test
    public void testLogoutResponse() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String status = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Element logoutResponse = createLogoutResponse(status, TEST_REQUEST_URL, true, requestId);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter("SAMLResponse")).andReturn(encodeResponse(logoutResponse)).anyTimes();
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getParameter("wa")).andReturn(null).times(2);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);

        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assertions.assertTrue(logoutHandler.canHandleRequest(req));

        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedLogoutRedirect = "https://localhost/secure/logout/redir.html";
        EasyMock.expect(resp.encodeRedirectURL(expectedLogoutRedirect)).andReturn(expectedLogoutRedirect);
        resp.sendRedirect(expectedLogoutRedirect);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }

    @org.junit.jupiter.api.Test
    public void testUnsignedLogoutResponse() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String status = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Element logoutResponse = createLogoutResponse(status, TEST_REQUEST_URL, false, requestId);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter("SAMLResponse")).andReturn(encodeResponse(logoutResponse)).anyTimes();
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getParameter("wa")).andReturn(null).times(2);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);

        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assertions.assertTrue(logoutHandler.canHandleRequest(req));

        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to validate SAMLResponse.");
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }

    @org.junit.jupiter.api.Test
    public void testUntrustedLogoutResponse() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("CLIENT_TRUST");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String status = "urn:oasis:names:tc:SAML:2.0:status:Success";
        Element logoutResponse = createLogoutResponse(status, TEST_REQUEST_URL, false, requestId);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter("SAMLResponse")).andReturn(encodeResponse(logoutResponse)).anyTimes();
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getParameter("wa")).andReturn(null).times(2);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);

        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assertions.assertTrue(logoutHandler.canHandleRequest(req));

        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to validate SAMLResponse.");
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }

    @org.junit.jupiter.api.Test
    public void validateBadStatusInLogoutResponse() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String status = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        Element logoutResponse = createLogoutResponse(status, TEST_REQUEST_URL, false, requestId);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter("SAMLResponse")).andReturn(encodeResponse(logoutResponse)).anyTimes();
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getParameter("wa")).andReturn(null).times(2);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);

        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assertions.assertTrue(logoutHandler.canHandleRequest(req));

        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to validate SAMLResponse.");
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }


    private Element createLogoutResponse(String statusValue, String destination,
                                         boolean sign, String requestID) throws Exception {
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(statusValue, null);
        LogoutResponse response =
            SAML2PResponseComponentBuilder.createSAMLLogoutResponse(requestID, TEST_IDP_ISSUER, status, destination);

        // Sign the LogoutResponse
        if (sign) {
            signResponse(response, "mystskey");
        }

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }

    private void signResponse(SignableSAMLObject signableObject, String alias) throws Exception {

        Signature signature = OpenSAMLUtil.buildSignature();
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(alias);
        X509Certificate[] issuerCerts = crypto.getX509Certificates(cryptoType);

        String sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if ("DSA".equalsIgnoreCase(pubKeyAlgo)) {
            sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_DSA;
        } else if ("EC".equalsIgnoreCase(pubKeyAlgo)) {
            sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1;
        }

        WSPasswordCallback[] cb = {
            new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        PrivateKey privateKey;
        try {
            privateKey = crypto.getPrivateKey(alias, password);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex);
        }
        if (privateKey == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                new Object[] {"No private key was found using issuer name: " + alias});
        }

        signature.setSignatureAlgorithm(sigAlgo);

        BasicX509Credential signingCredential =
            new BasicX509Credential(issuerCerts[0], privateKey);

        signature.setSigningCredential(signingCredential);

        X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
        kiFactory.setEmitEntityCertificate(true);

        try {
            KeyInfo keyInfo = kiFactory.newInstance().generate(signingCredential);
            signature.setKeyInfo(keyInfo);
        } catch (org.opensaml.security.SecurityException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "empty",
                new Object[] {"Error generating KeyInfo from signing credential"});
        }

        signableObject.setSignature(signature);
        String digestAlg = SignatureConstants.ALGO_ID_DIGEST_SHA1;
        SAMLObjectContentReference contentRef =
            (SAMLObjectContentReference)signature.getContentReferences().get(0);
        contentRef.setDigestAlgorithm(digestAlg);
        signableObject.releaseDOM();
        signableObject.releaseChildrenDOM(true);
    }

    private String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);

        byte[] deflatedBytes = CompressionUtils.deflate(responseMessage.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(deflatedBytes);
    }

}