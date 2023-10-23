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
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.common.STSUtil;
import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.AbstractSAMLCallbackHandler;
import org.apache.cxf.fediz.core.AbstractSAMLCallbackHandler.MultiValue;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.SAML1CallbackHandler;
import org.apache.cxf.fediz.core.SAML2CallbackHandler;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.Protocol;
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
import org.apache.cxf.fediz.core.processor.FederationProcessorImpl;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Some tests for the WS-Federation "FederationProcessor".
 */
public class FederationResponseTest {
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

    private static final String CONFIG_FILE = "fediz_test_config.xml";

    private static Crypto crypto;
    private static CallbackHandler cbPasswordHandler;
    private static FedizConfigurator configurator;


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


    /**
     * Validate RSTR without RequestedSecurityToken element
     */
    @org.junit.jupiter.api.Test
    public void validateRSTRWithoutToken() throws Exception {
        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(DOM2Writer.nodeToString(doc));

        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
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
    @org.junit.jupiter.api.Test
    public void validateRequestUnknownAction() throws Exception {
        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction("gugus");
        wfReq.setResponseToken(DOM2Writer.nodeToString(doc));

        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
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
    @org.junit.jupiter.api.Test
    public void validateSignInInvalidWResult() throws Exception {
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken("gugus");

        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected due to invalid wresult");
        } catch (ProcessingException ex) {
            if (!TYPE.INVALID_REQUEST.equals(ex.getType())) {
                fail("Expected ProcessingException with INVALID_REQUEST type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void validateTokenAndCreateMetadata() throws Exception {
        validateSAML2Token();
        FederationMetaDataTest other = new FederationMetaDataTest();
        other.validateMetaDataWithAlias();
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());

    }

    @org.junit.jupiter.api.Test
    public void testChainTrust() throws Exception {
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

        // Test successful trust validation (subject cert constraint)
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("CHAIN_TRUST");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");

        // Test unsuccessful trust validation (bad subject cert constraint)
        configurator = null;
        config = getFederationConfigurator().getFedizContext("CHAIN_TRUST2");

        wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            Assertions.fail("Processing must fail because of invalid subject cert constraint");
        } catch (ProcessingException ex) {
            // expected
        }
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     * Not RequestedSecurityTokenCollection in this test, default in all others
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
    }

    @org.junit.jupiter.api.Test
    public void validateSAML2TokenSubjectWithComment() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        String subject = "alice<!---->o=example.com";
        callbackHandler.setSubjectName(subject);
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

        Assertions.assertEquals(subject, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
    }

    /**
     * Validate SAML 2 token which doesn't include the role SAML attribute
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertNull(wfRes.getRoles());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
    }

    /**
     * Validate SAML 2 token where role information is provided
     * within another SAML attribute
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }

    /**
     * Validate SAML 1 token where role information is provided
     * within another SAML attribute
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }

    /**
     * Validate SAML 2 token which includes role attribute
     * but RoleURI is not configured
     */
    @org.junit.jupiter.api.Test
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
        config.getProtocol().setRoleURI(null);

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertNull(wfRes.getRoles());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
    }

    /**
     * Validate SAML 1.1 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }

    /**
     * Validate SAML 1.1 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     * Token embedded in RSTR 2005/02 - WS Federation 1.0
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multiple saml attributes with the same name
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a single saml attribute with encoded value
     */
    @org.junit.jupiter.api.Test
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
        Protocol protocol = config.getProtocol();
        protocol.setRoleDelimiter(",");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }
    
    @org.junit.jupiter.api.Test
    public void validateSAML2TokenEmptyRole() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setRoles(Collections.singletonList(""));
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
        Protocol protocol = config.getProtocol();
        protocol.setRoleDelimiter(",");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(1, wfRes.getRoles().size());
        Assertions.assertEquals("", wfRes.getRoles().get(0));
    }
    
    @org.junit.jupiter.api.Test
    public void validateSAML2TokenNoRoleValue() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setAddRoleValue(false);
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
        Protocol protocol = config.getProtocol();
        protocol.setRoleDelimiter(",");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertNull(wfRes.getRoles());
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * The configured subject of the trusted issuer doesn't match with
     * the issuer of the SAML token
     *
     * Ignored because PeerTrust ignores subject attribute
     */
    @org.junit.jupiter.api.Test
    @org.junit.jupiter.api.Disabled
    public void validateSAML2TokenUntrustedIssuer() throws Exception {
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
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        config.getTrustedIssuers().get(0).setSubject("wrong-issuer-name");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            Assertions.fail("Processing must fail because of untrusted issuer configured");
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
    @org.junit.jupiter.api.Test
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
            Assertions.fail("Processing must fail because of missing signature");
        } catch (ProcessingException ex) {
            if (!TYPE.TOKEN_NO_SIGNATURE.equals(ex.getType())) {
                fail("Expected ProcessingException with TOKEN_NO_SIGNATURE type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testUnsignedAssertionAfterSignedAssertion() throws Exception {
        // First assertion
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
        SamlAssertionWrapper assertion1 = new SamlAssertionWrapper(samlCallback);

        // Second assertion
        SAML2CallbackHandler callbackHandler2 = new SAML2CallbackHandler();
        callbackHandler2.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler2.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler2.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler2.setSubjectName("bob");
        ConditionsBean cp2 = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction2 = new AudienceRestrictionBean();
        audienceRestriction2.getAudienceURIs().add(TEST_AUDIENCE);
        cp2.setAudienceRestrictions(Collections.singletonList(audienceRestriction2));
        callbackHandler2.setConditions(cp2);

        SAMLCallback samlCallback2 = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler2, samlCallback2);
        SamlAssertionWrapper assertion2 = new SamlAssertionWrapper(samlCallback2);

        Element rstrElement =
            createResponseWithMultipleAssertions(assertion1, true, assertion2, false, "mystskey");
        String rstr = DOM2Writer.nodeToString(rstrElement);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);

        // Load and update the config to enforce an error
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse fedizResponse = wfProc.processRequest(wfReq, config);
        Assertions.assertEquals(TEST_USER, fedizResponse.getUsername());
    }

    @org.junit.jupiter.api.Test
    public void testSignedAssertionAfterUnsignedAssertion() throws Exception {
        // First assertion
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
        SamlAssertionWrapper assertion1 = new SamlAssertionWrapper(samlCallback);

        // Second assertion
        SAML2CallbackHandler callbackHandler2 = new SAML2CallbackHandler();
        callbackHandler2.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler2.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler2.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler2.setSubjectName("bob");
        ConditionsBean cp2 = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction2 = new AudienceRestrictionBean();
        audienceRestriction2.getAudienceURIs().add(TEST_AUDIENCE);
        cp2.setAudienceRestrictions(Collections.singletonList(audienceRestriction2));
        callbackHandler2.setConditions(cp2);

        SAMLCallback samlCallback2 = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler2, samlCallback2);
        SamlAssertionWrapper assertion2 = new SamlAssertionWrapper(samlCallback2);

        Element rstrElement =
            createResponseWithMultipleAssertions(assertion2, false, assertion1, true, "mystskey");
        String rstr = DOM2Writer.nodeToString(rstrElement);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);

        // Load and update the config to enforce an error
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            Assertions.fail("Processing must fail because of missing signature");
        } catch (ProcessingException ex) {
            if (!TYPE.TOKEN_NO_SIGNATURE.equals(ex.getType())) {
                fail("Expected ProcessingException with TOKEN_NO_SIGNATURE type");
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testWrappingAttack() throws Exception {
        // First assertion
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
        SamlAssertionWrapper assertion1 = new SamlAssertionWrapper(samlCallback);

        // Second assertion
        SAML2CallbackHandler callbackHandler2 = new SAML2CallbackHandler();
        callbackHandler2.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler2.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler2.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler2.setSubjectName("bob");
        ConditionsBean cp2 = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction2 = new AudienceRestrictionBean();
        audienceRestriction2.getAudienceURIs().add(TEST_AUDIENCE);
        cp2.setAudienceRestrictions(Collections.singletonList(audienceRestriction2));
        callbackHandler2.setConditions(cp2);

        SAMLCallback samlCallback2 = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler2, samlCallback2);
        SamlAssertionWrapper assertion2 = new SamlAssertionWrapper(samlCallback2);

        WSPasswordCallback[] cb = {
            new WSPasswordCallback("mystskey", WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        assertion1.signAssertion("mystskey", password, crypto, false);
        assertion2.signAssertion("mystskey", password, crypto, false);

        Document doc = STSUtil.toSOAPPart(SAMPLE_MULTIPLE_RSTR_COLL_MSG);
        Element token1 = assertion2.toDOM(doc);
        Element token2 = assertion1.toDOM(doc);

        // Now modify the first Signature to point to the other Element
        Element sig1 = XMLUtils.findElement(token1, "Signature", WSConstants.SIG_NS);
        Element sig2 = XMLUtils.findElement(token2, "Signature", WSConstants.SIG_NS);
        sig1.getParentNode().replaceChild(sig2.cloneNode(true), sig1);

        List<Element> requestedTokenElements =
            XMLUtils.findElements(doc, "RequestedSecurityToken", FederationConstants.WS_TRUST_13_NS);
        Assertions.assertEquals(2, requestedTokenElements.size());
        requestedTokenElements.get(0).appendChild(token1);
        requestedTokenElements.get(1).appendChild(token2);

        Element rstrElement = doc.getDocumentElement();

        String rstr = DOM2Writer.nodeToString(rstrElement);
        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);

        // Load and update the config to enforce an error
        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            Assertions.fail("Processing must fail because of bad signature");
        } catch (ProcessingException ex) {
            // expected
        }
    }

    private Element createResponseWithMultipleAssertions(SamlAssertionWrapper assertion1,
                                          boolean signFirstAssertion,
                                          SamlAssertionWrapper assertion2,
                                          boolean signSecondAssertion,
                                          String alias) throws Exception {
        WSPasswordCallback[] cb = {
            new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        if (signFirstAssertion) {
            assertion1.signAssertion(alias, password, crypto, false);
        }
        if (signSecondAssertion) {
            assertion2.signAssertion(alias, password, crypto, false);
        }

        Document doc = STSUtil.toSOAPPart(SAMPLE_MULTIPLE_RSTR_COLL_MSG);
        Element token1 = assertion1.toDOM(doc);
        Element token2 = assertion2.toDOM(doc);

        List<Element> requestedTokenElements =
            XMLUtils.findElements(doc, "RequestedSecurityToken", FederationConstants.WS_TRUST_13_NS);
        Assertions.assertEquals(2, requestedTokenElements.size());
        requestedTokenElements.get(0).appendChild(token1);
        requestedTokenElements.get(1).appendChild(token2);

        return doc.getDocumentElement();
    }

    /**
     * Validate SAML 2 token twice which causes an exception
     * due to replay attack
     */
    @org.junit.jupiter.api.Test
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
        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");

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
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
    }

    /**
     * Validate SAML 2 token which includes the role attribute with 2 values
     * The configured subject of the trusted issuer doesn't match with
     * the issuer of the SAML token
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
    }

    /**
     * Validate SAML 2 token which is expired
     */
    @org.junit.jupiter.api.Test
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
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
    }

    /**
     * "Validate" SAML 2 token with a custom token validator
     * If a validator is configured it precedes the SAMLTokenValidator as part of Fediz
     */
    @org.junit.jupiter.api.Test
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
        Protocol protocol = config.getProtocol();
        List<TokenValidator> validators = protocol.getTokenValidators();
        Assertions.assertEquals(2, validators.size());
        Assertions.assertEquals(CustomValidator.class.getName(), validators.get(0).getClass().getName(),
                "First validator must be custom validator");

        FedizProcessor wfProc = new FederationProcessorImpl();
        FedizResponse wfRes = wfProc.processRequest(wfReq, config);

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
    }

    /**
     * "Validate" SAML 2 token with a custom token validator
     * If a validator is configured it precedes the SAMLTokenValidator as part of Fediz
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
    }

    /**
     * Validate an encrypted SAML 2 token which includes the role attribute with 2 values
     * Roles are encoded as a multi-value saml attribute
     */
    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");
        assertClaims(wfRes.getClaims(), callbackHandler.getRoleAttributeName());
    }

    /**
     * Validate a HolderOfKey SAML 2 token
     */
    @org.junit.jupiter.api.Test
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

        Element e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = XMLUtils.findElement(doc, "RequestedSecurityToken",
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

    @org.junit.jupiter.api.Test
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

        Assertions.assertEquals(TEST_USER, wfRes.getUsername(), "Principal name wrong");
        Assertions.assertEquals(TEST_RSTR_ISSUER, wfRes.getIssuer(), "Issuer wrong");
        Assertions.assertEquals(2, wfRes.getRoles().size());
        Assertions.assertEquals(TEST_AUDIENCE, wfRes.getAudience(), "Audience wrong");

        fedContext.close();

    }

    @org.junit.jupiter.api.Test
    public void testModifiedSignature() throws Exception {
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

        WSPasswordCallback[] cb = {
            new WSPasswordCallback("mystskey", WSPasswordCallback.SIGNATURE)
        };
        cbPasswordHandler.handle(cb);
        String password = cb[0].getPassword();

        assertion.signAssertion("mystskey", password, crypto, false);
        Document doc = STSUtil.toSOAPPart(STSUtil.SAMPLE_RSTR_COLL_MSG);
        Element token = assertion.toDOM(doc);

        // Change IssueInstant attribute
        String issueInstance = token.getAttributeNS(null, "IssueInstant");
        DateTime issueDateTime = new DateTime(issueInstance, DateTimeZone.UTC);
        issueDateTime = issueDateTime.plusSeconds(1);
        token.setAttributeNS(null, "IssueInstant", issueDateTime.toString());

        Element e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                       FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                   FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
        String rstr = DOM2Writer.nodeToString(doc);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);

        configurator = null;
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on signature validation");
        } catch (ProcessingException ex) {
            // expected
        }
    }

    @org.junit.jupiter.api.Test
    public void testTrustFailure() throws Exception {
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
        FedizContext config = getFederationConfigurator().getFedizContext("CLIENT_TRUST");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on non-trusted signing cert");
        } catch (ProcessingException ex) {
            // expected
        }
    }

    @org.junit.jupiter.api.Test
    public void testUnableToFindTruststore() throws Exception {
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
        FedizContext config = getFederationConfigurator().getFedizContext("BAD_KEYSTORE");

        FedizProcessor wfProc = new FederationProcessorImpl();
        try {
            wfProc.processRequest(wfReq, config);
            fail("Failure expected on being unable to find the truststore");
        } catch (ProcessingException ex) {
            ex.printStackTrace();
            // expected
        }
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

        Element e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);

        WSSecEncrypt builder = new WSSecEncrypt(token.getOwnerDocument());
        builder.setUserInfo("mystskey");

        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);
        builder.setEmbedEncryptedKey(true);

        WSEncryptionPart encryptionPart = new WSEncryptionPart(assertion.getId(), "Element");
        encryptionPart.setElement(token);

        Crypto encrCrypto = CryptoFactory.getInstance("signature.properties");

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(builder.getSymmetricEncAlgorithm());
        SecretKey symmetricKey = keyGen.generateKey();

        builder.prepare(encrCrypto, symmetricKey);
        builder.encryptForRef(null, Collections.singletonList(encryptionPart), symmetricKey);

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

        Element e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                        FederationConstants.WS_TRUST_13_NS);
        if (e == null) {
            e = XMLUtils.findElement(doc, "RequestedSecurityToken",
                                                    FederationConstants.WS_TRUST_2005_02_NS);
        }
        e.appendChild(token);
        return DOM2Writer.nodeToString(doc);
    }

    private void assertClaims(List<Claim> claims, String roleClaimType) {
        URI roleClaimTypeURI = URI.create(roleClaimType);
        for (Claim c : claims) {
            Assertions.assertTrue(c.getClaimType().equals(roleClaimTypeURI)
                              || c.getClaimType().equals(ClaimTypes.COUNTRY)
                              || c.getClaimType().equals(AbstractSAMLCallbackHandler.CLAIM_TYPE_LANGUAGE),
                    "Invalid ClaimType URI: " + c.getClaimType());
        }
    }


}
