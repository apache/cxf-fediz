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
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.cxf.fediz.common.STSUtil;
import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.AbstractSAMLCallbackHandler;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
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
import org.apache.xml.security.utils.Base64;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;

import static org.junit.Assert.fail;

/**
 * Some tests for processing SAMLResponses using the SAMLProcessorImpl
 */
public class SAMLResponseTest {
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
    
    /**
     * Successfully validate a SAMLResponse
     */
    @org.junit.Test
    public void validateSAMLResponse() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                                                     TEST_IDP_ISSUER,
                                                     requestId,
                                                     TEST_REQUEST_URL,
                                                     (String)config.getProtocol().getIssuer(),
                                                     null,
                                                     System.currentTimeMillis());
        
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        ((SAMLProtocol)config.getProtocol()).getStateManager().setRequestState(relayState, requestState);
        
        // Create SAML Response
        String responseStr = createSamlResponseStr(requestId);
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        
        FedizProcessor wfProc = new SAMLProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_IDP_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_REQUEST_URL, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), FederationConstants.DEFAULT_ROLE_URI.toString());
    }
    
    /**
     * Validate SAMLResponse with a Response without an internal token parameter
     */
    @org.junit.Test
    public void validateResponseWithoutToken() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                                                     TEST_IDP_ISSUER,
                                                     requestId,
                                                     TEST_REQUEST_URL,
                                                     (String)config.getProtocol().getIssuer(),
                                                     null,
                                                     System.currentTimeMillis());
        
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        ((SAMLProtocol)config.getProtocol()).getStateManager().setRequestState(relayState, requestState);
        
        Document doc = STSUtil.toSOAPPart(SAMLSSOTestUtils.SAMPLE_EMPTY_SAML_RESPONSE);
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(DOM2Writer.nodeToString(doc));
        wfReq.setState(relayState);
        wfReq.setRequest(req);
        
        FedizProcessor wfProc = new SAMLProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on missing security token in response");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with BAD_REQUEST type");
            }
        }
    }
    
    @org.junit.Test
    public void testMissingRelayState() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                                                     TEST_IDP_ISSUER,
                                                     requestId,
                                                     TEST_REQUEST_URL,
                                                     (String)config.getProtocol().getIssuer(),
                                                     null,
                                                     System.currentTimeMillis());
        
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        ((SAMLProtocol)config.getProtocol()).getStateManager().setRequestState(relayState, requestState);
        
        // Create SAML Response
        String responseStr = createSamlResponseStr(requestId);
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setRequest(req);
        
        FedizProcessor wfProc = new SAMLProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on missing relay state in response");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with BAD_REQUEST type");
            }
        }
    }
    
    @org.junit.Test
    public void testNonMatchingRelayState() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        String requestId = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        
        RequestState requestState = new RequestState(TEST_REQUEST_URL,
                                                     TEST_IDP_ISSUER,
                                                     requestId,
                                                     TEST_REQUEST_URL,
                                                     (String)config.getProtocol().getIssuer(),
                                                     null,
                                                     System.currentTimeMillis());
        
        String relayState = URLEncoder.encode(UUID.randomUUID().toString(), "UTF-8");
        ((SAMLProtocol)config.getProtocol()).getStateManager().setRequestState(relayState, requestState);
        
        // Create SAML Response
        String responseStr = createSamlResponseStr(requestId);
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getRemoteAddr()).andReturn(TEST_CLIENT_ADDRESS);
        EasyMock.replay(req);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setResponseToken(responseStr);
        wfReq.setState("XYZ=");
        wfReq.setRequest(req);
        
        FedizProcessor wfProc = new SAMLProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on non matching relay state in response");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with BAD_REQUEST type");
            }
        }
    }
    
    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
    @org.junit.Test
    public void validateSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
        
    }
    
    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     * Not RequestedSecurityTokenCollection in this test, default in all others
    @org.junit.Test
    public void validateSAML2TokenRSTR() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true, STSUtil.SAMPLE_RSTR_MSG);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 2 token which doesn't include the role SAML attribute
    @org.junit.Test
    public void validateSAML2TokenWithoutRoles() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoles(null);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("No roles must be found", null, wfRes.getRoles());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 2 token where role information is provided
     * within another SAML attribute
    @org.junit.Test
    public void validateSAML2TokenDifferentRoleURI() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoleAttributeName("http://schemas.mycompany.com/claims/role");
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("CUSTOMROLEURI");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER, wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles().size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate SAML 2 token where role information is provided
     * within another SAML attribute
    @org.junit.Test
    public void validateSAML1TokenDifferentRoleURI() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoleAttributeName("http://schemas.mycompany.com/claims/role");
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("CUSTOMROLEURI");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER, wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles().size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate SAML 2 token which includes role attribute
     * but RoleURI is not configured
    @org.junit.Test
    public void validateSAML2TokenRoleURINotConfigured() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        ((FederationProtocol)config.getProtocol()).setRoleURI(null);
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", null, wfRes.getRoles());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 1.1 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
    @org.junit.Test
    public void validateSAML1Token() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate SAML 1.1 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     * Token embedded in RSTR 2005/02 - WS Federation 1.0
    @org.junit.Test
    public void validateSAML1TokenWSFed10() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true, STSUtil.SAMPLE_RSTR_2005_02_MSG);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multiple saml attributes with the same name
    @org.junit.Test
    public void validateSAML2TokenRoleMultiAttributes() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setMultiValueType(MultiValue.MULTI_ATTR);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a single saml attribute with encoded value
    @org.junit.Test
    public void validateSAML2TokenRoleEncodedValue() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setMultiValueType(MultiValue.ENC_VALUE);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        FederationProtocol fp = (FederationProtocol)config.getProtocol();
        fp.setRoleDelimiter(",");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * The configured subject of the trusted issuer doesn't match with
     * the issuer of the SAML token
    @org.junit.Test
    public void validateUnsignedSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", false);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");       
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            Assert.fail("Processing must fail because of missing signature");
        } catch (ProcessingException ex) {
            if (!TYPE.TOKEN_NO_SIGNATURE.equals(ex.getType())) {
                fail("Expected ProcessingException with TOKEN_NO_SIGNATURE type");
            }
        }
    }
    
    /**
     * Validate SAML 2 token twice which causes an exception
     * due to replay attack
    @org.junit.Test
    public void testReplayAttack() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        Assert.assertEquals("Principal name wrong", TEST_USER,
                wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        
        wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on a replay attack");
        } catch (ProcessingException ex) {
            if (!TYPE.TOKEN_REPLAY.equals(ex.getType())) {
                fail("Expected ProcessingException with TOKEN_REPLAY type");
            }
        }
    }
    
    
    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * The configured subject of the trusted issuer doesn't match with
     * the issuer of the SAML token
    @org.junit.Test
    public void validateSAML2TokenSeveralCertStore() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT2");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * The configured subject of the trusted issuer doesn't match with
     * the issuer of the SAML token
    @org.junit.Test
    public void validateSAML2TokenSeveralCertStoreTrustedIssuer() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT3");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
    }
    
    /**
     * Validate SAML 2 token which is expired
    @org.junit.Test
    public void validateSAML2TokenExpired() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        DateTime currentTime = new DateTime();
        currentTime = currentTime.minusSeconds(60);
        cp.setNotAfter(currentTime);
        currentTime = new DateTime();
        currentTime = currentTime.minusSeconds(300);
        cp.setNotBefore(currentTime);
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on expired SAML token");
        } catch (ProcessingException ex) {
            if (!TYPE.TOKEN_EXPIRED.equals(ex.getType())) {
                fail("Expected ProcessingException with TOKEN_EXPIRED type");
            }
        }
    }
    
    /**
     * Validate SAML 2 token which is not yet valid (in 30 seconds)
     * but within the maximum clock skew range (60 seconds)
    @org.junit.Test
    public void validateSAML2TokenClockSkewRange() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        DateTime currentTime = new DateTime();
        currentTime = currentTime.plusSeconds(300);
        cp.setNotAfter(currentTime);
        currentTime = new DateTime();
        currentTime = currentTime.plusSeconds(30);
        cp.setNotBefore(currentTime);
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        config.setMaximumClockSkew(BigInteger.valueOf(60));
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
    }

    /**
     * "Validate" SAML 2 token with a custom token validator
     * If a validator is configured it precedes the SAMLTokenValidator as part of Fediz
    @org.junit.Test
    public void validateSAML2TokenCustomValidator() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("CUSTTOK");
        FederationProtocol fp = (FederationProtocol)config.getProtocol();
        List<TokenValidator> validators = fp.getTokenValidators();
        Assert.assertEquals("Two validators must be found", 2, validators.size());
        Assert.assertEquals("First validator must be custom validator",
                            CustomValidator.class.getName(), validators.get(0).getClass().getName());
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
    }

    /**
     * "Validate" SAML 2 token with a custom token validator
     * If a validator is configured it precedes the SAMLTokenValidator as part of Fediz
    @org.junit.Test
    public void validateSAML2TokenMaxClockSkewNotDefined() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("NOCLOCKSKEW");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate an encrypted SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
    @org.junit.Test
    public void validateEncryptedSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = encryptAndSignToken(assertion);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = 
            getFederationConfigurator().getFedizContext("ROOT_DECRYPTION");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate a HolderOfKey SAML 2 token
    @org.junit.Test
    public void validateHOKSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        Crypto clientCrypto = CryptoFactory.getInstance("client-crypto.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("myclientkey");
        X509Certificate[] certs = clientCrypto.getX509Certificates(cryptoType);
        callbackHandler.setCerts(certs);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        WSPasswordCallback[] cb = {
            new WSPasswordCallback("mystskey", WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        assertion.signAssertion("mystskey", password, crypto, false);

        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);
        Element token = assertion.toDOM(doc);

        Element e = SAMLProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = SAMLProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
                               
        String rstr = DOM2Writer.nodeToString(doc);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
        
        configurator = null;
        FedizContext config = 
            getFederationConfigurator().getFedizContext("ROOT_DECRYPTION");
        
        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on missing client certs");
        } catch (ProcessingException ex) {
            // expected
        }
        
        // Now set client certs
        wfReq.setCerts(certs);      
        wfProc.processRequest(wfReq, config);
    }
    
    @org.junit.Test
    public void validateSAML2TokenWithConfigCreatedWithAPI() throws Exception {
        
        ContextConfig config = new ContextConfig();
        
        config.setName("whatever");

        // Configure certificate store
        CertificateStores certStores = new CertificateStores();
        TrustManagersType tm0 = new TrustManagersType();       
        KeyStoreType ks0 = new KeyStoreType();
        ks0.setType("JKS");
        ks0.setPassword("storepass");
        ks0.setFile("ststrust.jks");
        tm0.setKeyStore(ks0);
        certStores.getTrustManager().add(tm0);
        config.setCertificateStores(certStores);
        
        // Configure trusted IDP
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        TrustedIssuerType ti0 = new TrustedIssuerType();
        ti0.setCertificateValidation(ValidationType.CHAIN_TRUST);
        ti0.setName("FedizSTSIssuer");
        ti0.setSubject(".*CN=www.sts.com.*");
        trustedIssuers.getIssuer().add(ti0);
        config.setTrustedIssuers(trustedIssuers);

        FederationProtocolType protocol = new FederationProtocolType();
        config.setProtocol(protocol);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add("https://localhost/fedizhelloworld");
        config.setAudienceUris(audienceUris);

        protocol.setRoleURI("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role");

        FedizContext fedContext = new FedizContext(config);
        fedContext.init();
        
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(TEST_AUDIENCE);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true, STSUtil.SAMPLE_RSTR_MSG);
        
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);
                
        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, fedContext);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        
        fedContext.close();

    }
    */
    
    private String createSamlResponseStr(String requestId) throws Exception {
        // Create SAML Assertion
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
        Element response = createSamlResponse(assertion, "mystskey", true, requestId);
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
        Document doc = docBuilder.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(
                "urn:oasis:names:tc:SAML:2.0:status:Success", null
            );
        Response response =
            SAML2PResponseComponentBuilder.createSAMLResponse(requestID, 
                                                              assertion.getIssuerString(), 
                                                              status);

        response.getAssertions().add(assertion.getSaml2());

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }
    

    
    
    /**
     * Returns the first element that matches <code>name</code> and
     * <code>namespace</code>. <p/> This is a replacement for a XPath lookup
     * <code>//name</code> with the given namespace. It's somewhat faster than
     * XPath, and we do not deal with prefixes, just with the real namespace URI
     * 
     * @param startNode Where to start the search
     * @param name Local name of the element
     * @param namespace Namespace URI of the element
     * @return The found element or <code>null</code>
     */
    public static Element findElement(Node startNode, String name, String namespace) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE
                && startNode.getLocalName().equals(name)) {
                String ns = startNode.getNamespaceURI();
                if (ns != null && ns.equals(namespace)) {
                    return (Element)startNode;
                }

                if ((namespace == null || namespace.length() == 0)
                    && (ns == null || ns.length() == 0)) {
                    return (Element)startNode;
                }
            }
            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return null;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return null;
    }

    private void assertClaims(List<Claim> claims, String roleClaimType) {
        for (Claim c : claims) {
            Assert.assertTrue("Invalid ClaimType URI: " + c.getClaimType(), 
                              c.getClaimType().equals(roleClaimType)
                              || c.getClaimType().equals(ClaimTypes.COUNTRY)
                              || c.getClaimType().equals(AbstractSAMLCallbackHandler.CLAIM_TYPE_LANGUAGE)
                              );
        }
    }
    
    private String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);

        byte[] deflatedBytes = CompressionUtils.deflate(responseMessage.getBytes("UTF-8"));

        return Base64.encode(deflatedBytes);
    }


}
