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
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.cxf.fediz.core.SAML2CallbackHandler;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.core.processor.SAMLProcessorImpl;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
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
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;

import org.easymock.EasyMock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Some tests for processing SAMLResponses using the SAMLProcessorImpl, where the SAML Response
 * fails some requirement in the Web SSO profile spec.
 */
public class SAMLResponseConformanceTest {
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
    public void testWrongIssuerFormat() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        // The Issuer NameFormat must be "entity" if it is used at all
        String issuerNameFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
        Issuer issuer =
            SAML2PResponseComponentBuilder.createIssuer(assertion.getIssuerString(),
                                                        issuerNameFormat);

        Element response = createSamlResponse(assertion, "mystskey", true, requestId, issuer);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testRightIssuerFormat() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        // The Issuer NameFormat must be "entity" if it is used at all
        String issuerNameFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        Issuer issuer =
            SAML2PResponseComponentBuilder.createIssuer(assertion.getIssuerString(),
                                                        issuerNameFormat);

        Element response = createSamlResponse(assertion, "mystskey", true, requestId, issuer);
        String responseStr = encodeResponse(response);

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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_IDP_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_REQUEST_URL, wfRes.getAudience(), "Audience wrong");
    }

    @org.junit.jupiter.api.Test
    public void testNoAuthnStatement() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_IDP_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testAudienceRestriction() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNonMatchingAudienceRestriction() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL + "asf");
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNoBearerSubjectConfirmation() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer(TEST_IDP_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNonMatchingRecipient() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL + "asf");
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNonMatchingInResponseTo() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId + "123");
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNonMatchingAddress() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS + "xyz");
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNotBefore() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotBefore(new DateTime().minusMinutes(1));
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testNotOnOfAfter() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        Element response = createSamlResponse(assertion, "mystskey", true, requestId, null);
        String responseStr = encodeResponse(response);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testFailingStatusWithValidAssertion() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        WSPasswordCallback[] cb = {
            new WSPasswordCallback("mystskey", WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();
        assertion.signAssertion("mystskey", password, crypto, false);

        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(
                "urn:oasis:names:tc:SAML:2.0:status:Failure", null
            );

        Issuer responseIssuer =
            SAML2PResponseComponentBuilder.createIssuer(assertion.getIssuerString());

        Response response =
            SAML2PResponseComponentBuilder.createSAMLResponse(requestId,
                                                              responseIssuer,
                                                              status);

        response.getAssertions().add(assertion.getSaml2());

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        String responseStr = encodeResponse(policyElement);

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
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testIssuerEnforcementFailure() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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
        callbackHandler.setIssuer(TEST_IDP_ISSUER + "/other-issuer");
        callbackHandler.setSubjectName(TEST_USER);

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        Issuer issuer =
            SAML2PResponseComponentBuilder.createIssuer(assertion.getIssuerString());

        Element response = createSamlResponse(assertion, "mystskey", true, requestId, issuer);
        String responseStr = encodeResponse(response);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        wfReq.setRequestState(requestState);

        // Failure expected on an unknown issuer value
        FedizProcessor wfProc = new SAMLProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testIssuerEnforcementDisable() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

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
        callbackHandler.setIssuer(TEST_IDP_ISSUER + "/other-issuer");
        callbackHandler.setSubjectName(TEST_USER);

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_REQUEST_URL);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        // Subject Confirmation Data
        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress(TEST_CLIENT_ADDRESS);
        subjectConfirmationData.setInResponseTo(requestId);
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient(TEST_REQUEST_URL);
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        Issuer issuer =
            SAML2PResponseComponentBuilder.createIssuer(assertion.getIssuerString());

        Element response = createSamlResponse(assertion, "mystskey", true, requestId, issuer);
        String responseStr = encodeResponse(response);

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        wfReq.setRequestState(requestState);

        // Disable the issuer enforcement check
        FedizProcessor wfProc = new SAMLProcessorImpl();
        ((SAMLProtocol)config.getProtocol()).setDoNotEnforceKnownIssuer(true);
        Assertions.assertTrue(((SAMLProtocol)config.getProtocol()).isDoNotEnforceKnownIssuer());
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");

    }

    private Element createSamlResponse(SamlAssertionWrapper assertion, String alias,
                                      boolean sign, String requestID, Issuer issuer)
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
        Document doc = docBuilder.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(
                "urn:oasis:names:tc:SAML:2.0:status:Success", null
            );

        Issuer responseIssuer = issuer;
        if (responseIssuer == null) {
            responseIssuer = SAML2PResponseComponentBuilder.createIssuer(assertion.getIssuerString());
        }
        Response response =
            SAML2PResponseComponentBuilder.createSAMLResponse(requestID,
                                                              responseIssuer,
                                                              status);

        response.getAssertions().add(assertion.getSaml2());

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }

    private String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);

        byte[] deflatedBytes = CompressionUtils.deflate(responseMessage.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(deflatedBytes);
    }


}
