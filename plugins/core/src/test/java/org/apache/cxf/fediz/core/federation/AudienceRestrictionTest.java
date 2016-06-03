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

package org.apache.cxf.fediz.core.federation;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.common.STSUtil;
import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.SAML2CallbackHandler;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.XMLUtils;
import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * Some tests for audience restriction
 */
public class AudienceRestrictionTest {
    public static final String SAMPLE_MULTIPLE_RSTR_COLL_MSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<RequestSecurityTokenResponseCollection "
        +   "xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"> "
        +   "<RequestSecurityTokenResponse>"
        +     "<RequestedSecurityToken>"
        +     "</RequestedSecurityToken>"
        +   "</RequestSecurityTokenResponse>"
        +   "<RequestSecurityTokenResponse>"
        +     "<RequestedSecurityToken>"
        +     "</RequestedSecurityToken>"
        +   "</RequestSecurityTokenResponse>"
        + "</RequestSecurityTokenResponseCollection>";
    
    static final String TEST_USER = "alice";
    static final String TEST_RSTR_ISSUER = "FedizSTSIssuer";
    static final String TEST_AUDIENCE = "https://localhost/fedizhelloworld";
    static final String TEST_REQUEST_URL = "https://localhost/fedizhelloworld/";
    static final String TEST_REQUEST_URI = "/fedizhelloworld";
    
    private static final String CONFIG_FILE = "fediz_test_config_aud.xml";
    
    private static Crypto crypto;
    private static CallbackHandler cbPasswordHandler;
    private static FedizConfigurator configurator;
    
    
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
    public void validateAudienceThatIsRequired() throws Exception {
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
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("AUD1");
        
        // Mock up the servet request/response
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getMethod()).andReturn("POST");
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_RESULT)).andReturn(rstr);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNIN);
        String relayState = "asfnaosif123123";
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        EasyMock.replay(resp);
        
        // Now validate the request
        TestSigninHandler signinHandler = new TestSigninHandler(config);
        Assert.assertNotNull(signinHandler.handleRequest(req, resp));
    }
    
    @org.junit.Test
    public void validateAudienceThatIsRequiredAgainstMultipleAudiences() throws Exception {
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
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("AUD2");
        
        // Mock up the servet request/response
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getMethod()).andReturn("POST");
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_RESULT)).andReturn(rstr);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNIN);
        String relayState = "asfnaosif123123";
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        EasyMock.replay(resp);
        
        // Now validate the request
        TestSigninHandler signinHandler = new TestSigninHandler(config);
        Assert.assertNotNull(signinHandler.handleRequest(req, resp));
    }
    
    @org.junit.Test
    public void validateBadAudienceThatIsRequired() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add("https://localhost/badfedizhelloworld");
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("AUD1");
        
        // Mock up the servet request/response
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getMethod()).andReturn("POST");
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_RESULT)).andReturn(rstr);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNIN);
        String relayState = "asfnaosif123123";
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        EasyMock.replay(resp);
        
        // Now validate the request
        TestSigninHandler signinHandler = new TestSigninHandler(config);
        Assert.assertNull(signinHandler.handleRequest(req, resp));
    }
    
    @org.junit.Test
    public void validateNoAudienceThatIsRequired() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("AUD1");
        
        // Mock up the servet request/response
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getMethod()).andReturn("POST");
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_RESULT)).andReturn(rstr);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNIN);
        String relayState = "asfnaosif123123";
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        EasyMock.replay(resp);
        
        // Now validate the request
        TestSigninHandler signinHandler = new TestSigninHandler(config);
        Assert.assertNull(signinHandler.handleRequest(req, resp));
    }
    
    @org.junit.Test
    public void validateNoAudienceThatIsNotRequired() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("NOAUD");
        
        // Mock up the servet request/response
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getMethod()).andReturn("POST");
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_RESULT)).andReturn(rstr);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNIN);
        String relayState = "asfnaosif123123";
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        EasyMock.replay(resp);
        
        // Now validate the request
        TestSigninHandler signinHandler = new TestSigninHandler(config);
        Assert.assertNotNull(signinHandler.handleRequest(req, resp));
    }
    
    @org.junit.Test
    public void validateAudienceThatIsNotRequired() throws Exception {
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
        
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("NOAUD");
        
        // Mock up the servet request/response
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL));
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getMethod()).andReturn("POST");
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_RESULT)).andReturn(rstr);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNIN);
        String relayState = "asfnaosif123123";
        EasyMock.expect(req.getParameter("RelayState")).andReturn(relayState);
        EasyMock.expect(req.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        EasyMock.replay(resp);
        
        // Now validate the request
        TestSigninHandler signinHandler = new TestSigninHandler(config);
        Assert.assertNull(signinHandler.handleRequest(req, resp));
    }
    
    private String createSamlToken(SamlAssertionWrapper assertion, String alias, boolean sign)
        throws IOException, UnsupportedCallbackException, WSSecurityException, Exception {
        return createSamlToken(assertion, alias, sign, STSUtil.SAMPLE_RSTR_COLL_MSG);
    }
    
    private String createSamlToken(SamlAssertionWrapper assertion, String alias, boolean sign, String rstr)
        throws IOException, UnsupportedCallbackException, WSSecurityException, Exception {
        WSPasswordCallback[] cb = {
            new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        if (sign) {
            assertion.signAssertion(alias, password, crypto, false);
        }
        Document doc = STSUtil.toSOAPPart(rstr);
        Element token = assertion.toDOM(doc);

        Element e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
        return DOM2Writer.nodeToString(doc);
    }
    
}
