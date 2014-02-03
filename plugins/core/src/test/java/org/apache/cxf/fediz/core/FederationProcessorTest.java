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

package org.apache.cxf.fediz.core;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import junit.framework.Assert;

import org.apache.cxf.fediz.common.STSUtil;
import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.AbstractSAMLCallbackHandler.MultiValue;
import org.apache.cxf.fediz.core.config.FederationConfigurator;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.jaxb.AudienceUris;
import org.apache.cxf.fediz.core.config.jaxb.CertificateStores;
import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.joda.time.DateTime;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import static org.junit.Assert.fail;

public class FederationProcessorTest {
    static final String TEST_USER = "alice";
    static final String TEST_RSTR_ISSUER = "FedizSTSIssuer";
    static final String TEST_AUDIENCE = "https://localhost/fedizhelloworld";
    
    private static final String CONFIG_FILE = "fediz_test_config.xml";
    
    private static Crypto crypto;
    private static CallbackHandler cbPasswordHandler;
    private static FederationConfigurator configurator;
    
    
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
    

    private static FederationConfigurator getFederationConfigurator() {
        if (configurator != null) {
            return configurator;
        }
        try {
            configurator = new FederationConfigurator();
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
     * Validate RSTR without RequestedSecurityToken element
     */
    @org.junit.Test
    public void validateRSTRWithoutToken() throws Exception {
        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(DOM2Writer.nodeToString(doc));
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");

        FederationProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on missing security token in RSTR");
        } catch (ProcessingException ex) {
            if (!TYPE.BAD_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with BAD_REQUEST type");
            }
        }
    }
    
    /**
     * Validate FederationRequest with unknown action
     */
    @org.junit.Test
    public void validateRequestUnknownAction() throws Exception {
        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa("gugus");
        wfReq.setWresult(DOM2Writer.nodeToString(doc));
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");

        FederationProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected due to invalid action");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }
    
    /**
     *Validate FederationRequest with invalid RSTR/wresult
     */
    @org.junit.Test
    public void validateSignInInvalidWResult() throws Exception {
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult("gugus");
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");

        FederationProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected due to invalid wresult");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }
    
    @org.junit.Test
    public void validateTokenAndCreateMetadata() throws Exception {
        validateSAML2Token();
        FederationMetaDataTest other = new FederationMetaDataTest();
        other.validateMetaDataWithAlias();
    }
    
    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     */
    @org.junit.Test
    public void validateSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateSAML2TokenRSTR() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true, STSUtil.SAMPLE_RSTR_MSG);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 2 token which doesn't include the role SAML attribute
     */
    @org.junit.Test
    public void validateSAML2TokenWithoutRoles() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoles(null);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("No roles must be found", null, wfRes.getRoles());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 2 token where role information is provided
     * within another SAML attribute
     */
    @org.junit.Test
    public void validateSAML2TokenDifferentRoleURI() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoleAttributeName("http://schemas.mycompany.com/claims/role");
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("CUSTOMROLEURI");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER, wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles().size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate SAML 2 token where role information is provided
     * within another SAML attribute
     */
    @org.junit.Test
    public void validateSAML1TokenDifferentRoleURI() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoleAttributeName("http://schemas.mycompany.com/claims/role");
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("CUSTOMROLEURI");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER, wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles().size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    /**
     * Validate SAML 2 token which includes role attribute
     * but RoleURI is not configured
     */
    @org.junit.Test
    public void validateSAML2TokenRoleURINotConfigured() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        ((FederationProtocol)config.getProtocol()).setRoleURI(null);
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", null, wfRes.getRoles());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
    }
    
    /**
     * Validate SAML 1.1 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     */
    @org.junit.Test
    public void validateSAML1Token() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateSAML1TokenWSFed10() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true, STSUtil.SAMPLE_RSTR_2005_02_MSG);
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateSAML2TokenRoleMultiAttributes() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setMultiValueType(MultiValue.MULTI_ATTR);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");

        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateSAML2TokenRoleEncodedValue() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setMultiValueType(MultiValue.ENC_VALUE);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        FederationProtocol fp = (FederationProtocol)config.getProtocol();
        fp.setRoleDelimiter(",");

        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     * 
     * Ignored because PeerTrust ignores subject attribute
     */
    @org.junit.Test
    @org.junit.Ignore
    public void validateSAML2TokenUntrustedIssuer() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        config.getTrustedIssuers().get(0).setSubject("wrong-issuer-name");        
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            Assert.fail("Processing must fail because of untrusted issuer configured");
        } catch (ProcessingException ex) {
            if (!TYPE.ISSUER_NOT_TRUSTED.equals(ex.getType())) {
                fail("Expected ProcessingException with ISSUER_NOT_TRUSTED type");
            }
        }
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * The configured subject of the trusted issuer doesn't match with
     * the issuer of the SAML token
     */
    @org.junit.Test
    public void validateUnsignedSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", false);
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");       
        
        FederationProcessor wfProc = new FederationProcessorImpl();
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
     */
    @org.junit.Test
    public void testReplayAttack() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");

        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
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
     */
    @org.junit.Test
    public void validateSAML2TokenSeveralCertStore() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT2");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateSAML2TokenSeveralCertStoreTrustedIssuer() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        // Load and update the config to enforce an error
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT3");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
    }
    
    /**
     * Validate SAML 2 token which is expired
     */
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
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");

        FederationProcessor wfProc = new FederationProcessorImpl();
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
     */
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
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("ROOT");
        config.setMaximumClockSkew(BigInteger.valueOf(60));
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
    }

    /**
     * "Validate" SAML 2 token with a custom token validator
     * If a validator is configured it precedes the SAMLTokenValidator as part of Fediz
     */
    @org.junit.Test
    public void validateSAML2TokenCustomValidator() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("CUSTTOK");
        FederationProtocol fp = (FederationProtocol)config.getProtocol();
        List<TokenValidator> validators = fp.getTokenValidators();
        Assert.assertEquals("Two validators must be found", 2, validators.size());
        Assert.assertEquals("First validator must be custom validator",
                            CustomValidator.class.getName(), validators.get(0).getClass().getName());
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
    }

    /**
     * "Validate" SAML 2 token with a custom token validator
     * If a validator is configured it precedes the SAMLTokenValidator as part of Fediz
     */
    @org.junit.Test
    public void validateSAML2TokenMaxClockSkewNotDefined() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = getFederationConfigurator().getFederationContext("NOCLOCKSKEW");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateEncryptedSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = encryptAndSignToken(assertion);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = 
            getFederationConfigurator().getFederationContext("ROOT_DECRYPTION");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, config);
        
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
     */
    @org.junit.Test
    public void validateHOKSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
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

        Element e = FederationProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = FederationProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
                               
        String rstr = DOM2Writer.nodeToString(doc);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
        
        configurator = null;
        FederationContext config = 
            getFederationConfigurator().getFederationContext("ROOT_DECRYPTION");
        
        FederationProcessor wfProc = new FederationProcessorImpl();
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

        FederationContext fedContext = new FederationContext(config);
        fedContext.init();
        
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        ConditionsBean cp = new ConditionsBean();
        cp.setAudienceURI(TEST_AUDIENCE);
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        String rstr = createSamlToken(assertion, "mystskey", true, STSUtil.SAMPLE_RSTR_MSG);
        
        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(rstr);
                
        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfRes = wfProc.processRequest(wfReq, fedContext);
        
        Assert.assertEquals("Principal name wrong", TEST_USER,
                            wfRes.getUsername());
        Assert.assertEquals("Issuer wrong", TEST_RSTR_ISSUER, wfRes.getIssuer());
        Assert.assertEquals("Two roles must be found", 2, wfRes.getRoles()
                            .size());
        Assert.assertEquals("Audience wrong", TEST_AUDIENCE, wfRes.getAudience());
        
        fedContext.close();

    }
    
    
    private String encryptAndSignToken(
        SamlAssertionWrapper assertion
    ) throws Exception {
        
        WSPasswordCallback[] cb = {
            new WSPasswordCallback("mystskey", WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        assertion.signAssertion("mystskey", password, crypto, false);
        
        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);
        Element token = assertion.toDOM(doc);

        Element e = FederationProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = FederationProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("mystskey");
        
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);
        builder.setEmbedEncryptedKey(true);
        
        WSEncryptionPart encryptionPart = new WSEncryptionPart(assertion.getId(), "Element");
        encryptionPart.setElement(token);
        
        Crypto encrCrypto = CryptoFactory.getInstance("signature.properties");
        builder.prepare(token.getOwnerDocument(), encrCrypto);
        builder.encryptForRef(null, Collections.singletonList(encryptionPart));
        
        // return doc.getDocumentElement();
        return DOM2Writer.nodeToString(doc);
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

        Element e = FederationProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = FederationProcessorTest.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
        return DOM2Writer.nodeToString(doc);
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
    

}
