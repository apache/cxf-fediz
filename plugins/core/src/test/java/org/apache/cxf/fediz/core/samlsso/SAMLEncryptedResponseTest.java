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
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.AbstractSAMLCallbackHandler;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.cxf.fediz.core.SAML2CallbackHandler;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.core.processor.SAMLProcessorImpl;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.WSConstants;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.content.X509Data;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;

import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Some tests for processing SAMLResponses containing EncryptedAssertions using the SAMLProcessorImpl
 */
public class SAMLEncryptedResponseTest {
    static final String TEST_USER = "alice";
    static final String TEST_REQUEST_URL = "https://localhost/fedizhelloworld/";
    static final String TEST_REQUEST_URI = "/fedizhelloworld";
    static final String TEST_IDP_ISSUER = "http://url_to_the_issuer";
    static final String TEST_CLIENT_ADDRESS = "https://127.0.0.1";

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


    @BeforeClass
    public static void init() {
        try {
            crypto = CryptoFactory.getInstance("signature.properties");
            cbPasswordHandler = new KeystoreCallbackHandler();
            getFederationConfigurator();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(configurator);

    }

    @AfterClass
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

    @org.junit.Test
    public void validateSignedEncryptedSAMLResponse() throws Exception {
        // Mock up a Request
        FedizContext config =
                getFederationConfigurator().getFedizContext("ROOT_DECRYPTION");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                TEST_IDP_ISSUER,
                requestId,
                TEST_REQUEST_URL,
                (String)config.getProtocol().getIssuer(),
                null,
                relayState,
                System.currentTimeMillis());

        // Create SAML Response
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setAlsoAddAuthnStatement(true);
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_IDP_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        String responseStr = createSamlResponseStr(callbackHandler, requestId, true);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        wfReq.setRequestState(requestState);

        FedizProcessor wfProc = new SAMLProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assert.assertEquals("Principal name wrong", TEST_USER,
                wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_IDP_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                .size());
        Assert.assertEquals("Audience wrong", TEST_REQUEST_URL, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), ClaimTypes.COUNTRY);
    }

    @org.junit.Test
    public void validateUnsignedEncryptedSAMLResponse() throws Exception {
        // Mock up a Request
        FedizContext config =
                getFederationConfigurator().getFedizContext("ROOT_DECRYPTION_ALLOW_UNSIGNED");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                TEST_IDP_ISSUER,
                requestId,
                TEST_REQUEST_URL,
                (String)config.getProtocol().getIssuer(),
                null,
                relayState,
                System.currentTimeMillis());

        // Create SAML Response
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setAlsoAddAuthnStatement(true);
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_IDP_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        String responseStr = createSamlResponseStr(callbackHandler, requestId, false);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        wfReq.setRequestState(requestState);

        FedizProcessor wfProc = new SAMLProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assert.assertEquals("Principal name wrong", TEST_USER,
                wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_IDP_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                .size());
        Assert.assertEquals("Audience wrong", TEST_REQUEST_URL, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), ClaimTypes.COUNTRY);
    }

    @org.junit.Test
    public void rejectUnsignedEncryptedAssertionByDefault() throws Exception {
        // Mock up a Request
        FedizContext config =
                getFederationConfigurator().getFedizContext("ROOT_DECRYPTION");

        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");

        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                TEST_IDP_ISSUER,
                requestId,
                TEST_REQUEST_URL,
                (String)config.getProtocol().getIssuer(),
                null,
                relayState,
                System.currentTimeMillis());

        // Create SAML Response
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setAlsoAddAuthnStatement(true);
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_IDP_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        String responseStr = createSamlResponseStr(callbackHandler, requestId, false);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        wfReq.setRequestState(requestState);

        FedizProcessor wfProc = new SAMLProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on an unsigned token");
        } catch (ProcessingException ex) {
            // expected
        }
    }

    private String createSamlResponseStr(AbstractSAMLCallbackHandler saml2CallbackHandler,
                                         String requestId,
                                         boolean signAssertion) throws Exception {
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        saml2CallbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        saml2CallbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(saml2CallbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        Element response = createEncryptedSamlResponse(assertion, "mystskey", signAssertion, requestId);
        return encodeResponse(response);
    }

    private Element createSamlResponse(SamlAssertionWrapper assertion, String alias,
                                      boolean sign, String requestID)
        throws IOException, UnsupportedCallbackException, WSSecurityException, Exception {
        WSPasswordCallback[] cb = {
            new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        if (sign) {
            assertion.signAssertion(alias, password, crypto, false);
        }

        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(
                "urn:oasis:names:tc:SAML:2.0:status:Success", null
            );
        Response response =
            SAML2PResponseComponentBuilder.createSAMLResponse(requestID,
                                                              assertion.getIssuerString(),
                                                              status);
        response.getAssertions().add(assertion.getSaml2());

        Document doc = docBuilder.newDocument();
        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }

    private Element createEncryptedSamlResponse(SamlAssertionWrapper assertion, String alias,
                                       boolean sign, String requestID)
            throws IOException, UnsupportedCallbackException, WSSecurityException, Exception {
        WSPasswordCallback[] cb = {new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE)};
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        if (sign) {
            assertion.signAssertion(alias, password, crypto, false);
        }

        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();

        Status status =
                SAML2PResponseComponentBuilder.createStatus(
                        "urn:oasis:names:tc:SAML:2.0:status:Success", null
                );
        Response response =
                SAML2PResponseComponentBuilder.createSAMLResponse(requestID,
                        assertion.getIssuerString(),
                        status);

        Document assertionDoc = docBuilder.newDocument();
        Element elem = assertion.toDOM(assertionDoc);

        Element encryptedAssertionElement =
                assertionDoc.createElementNS(WSConstants.SAML2_NS, WSConstants.ENCRYPED_ASSERTION_LN);
        encryptedAssertionElement.setAttributeNS(
                WSConstants.XMLNS_NS, "xmlns", WSConstants.SAML2_NS
        );
        encryptedAssertionElement.appendChild(elem);
        assertionDoc.appendChild(encryptedAssertionElement);

        // Encrypt the Assertion
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey secretKey = keygen.generateKey();
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("mystskey");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0 && certs[0] != null);

        encryptElement(assertionDoc, elem, WSConstants.AES_256, secretKey,
                WSConstants.KEYTRANSPORT_RSAOAEP, certs[0], false);

        Document doc = docBuilder.newDocument();
        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        Element statusElement =
                (Element)policyElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol",
                        "Status").item(0);
        assertNotNull(statusElement);
        policyElement.appendChild(doc.importNode(encryptedAssertionElement, true));

        return policyElement;
    }

    private void assertClaims(List<Claim> claims, URI claimType) {
        boolean found = false;
        for (Claim c : claims) {
            if (c.getClaimType().equals(claimType)) {
                found = true;
                break;
            }
        }
        assertTrue(found);
    }

    private String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);

        byte[] deflatedBytes = CompressionUtils.deflate(responseMessage.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(deflatedBytes);
    }

    private void encryptElement(
            Document document,
            Element elementToEncrypt,
            String algorithm,
            Key encryptingKey,
            String keyTransportAlgorithm,
            X509Certificate wrappingCert,
            boolean content
    ) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.ENCRYPT_MODE, encryptingKey);

        if (wrappingCert != null) {
            XMLCipher newCipher = XMLCipher.getInstance(keyTransportAlgorithm);
            newCipher.init(XMLCipher.WRAP_MODE, wrappingCert.getPublicKey());

            EncryptedKey encryptedKey = newCipher.encryptKey(document, encryptingKey);
            // Create a KeyInfo for the EncryptedKey
            org.apache.xml.security.keys.KeyInfo encryptedKeyKeyInfo = encryptedKey.getKeyInfo();
            if (encryptedKeyKeyInfo == null) {
                encryptedKeyKeyInfo = new org.apache.xml.security.keys.KeyInfo(document);
                encryptedKeyKeyInfo.getElement().setAttributeNS(
                        "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
                );
                encryptedKey.setKeyInfo(encryptedKeyKeyInfo);
            }

            X509Data x509Data = new X509Data(document);
            // x509Data.addCertificate(wrappingCert);
            x509Data.addIssuerSerial(wrappingCert.getIssuerX500Principal().getName(),
                    wrappingCert.getSerialNumber());
            encryptedKeyKeyInfo.add(x509Data);

            // Create a KeyInfo for the EncryptedData
            EncryptedData builder = cipher.getEncryptedData();
            org.apache.xml.security.keys.KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new org.apache.xml.security.keys.KeyInfo(document);
                builderKeyInfo.getElement().setAttributeNS(
                        "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
                );
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);
        }

        cipher.doFinal(document, elementToEncrypt, content);
    }


}
