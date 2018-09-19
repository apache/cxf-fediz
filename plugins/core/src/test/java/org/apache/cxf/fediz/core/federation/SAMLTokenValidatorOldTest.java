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
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.cxf.fediz.common.STSUtil;
import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.AbstractSAMLCallbackHandler;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.SAML1CallbackHandler;
import org.apache.cxf.fediz.core.SAML2CallbackHandler;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.processor.FederationProcessorImpl;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
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
import org.apache.wss4j.common.util.XMLUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;


// This testcases tests the encoding implemented before CXF-4484
public class SAMLTokenValidatorOldTest {
    static final String TEST_USER = "alice";
    static final String TEST_RSTR_ISSUER = "FedizSTSIssuer";
    static final String TEST_AUDIENCE = "https://localhost/fedizhelloworld";

    private static final String CONFIG_FILE = "fediz_test_config.xml";

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
        callbackHandler.setAttributeNameFormat(ClaimTypes.URI_BASE.toString());
        callbackHandler.setCountryClaimName("country");
        callbackHandler.setRoleAttributeName("role");

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
        callbackHandler.setAttributeNameFormat(ClaimTypes.URI_BASE.toString());
        callbackHandler.setCountryClaimName("country");
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
     */
    @org.junit.Test
    public void validateSAML1TokenDifferentRoleURI() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(TEST_RSTR_ISSUER);
        callbackHandler.setSubjectName(TEST_USER);
        callbackHandler.setUseNameFormatAsNamespace(true);
        callbackHandler.setAttributeNameFormat(ClaimTypes.URI_BASE.toString());
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
        callbackHandler.setUseNameFormatAsNamespace(true);
        callbackHandler.setAttributeNameFormat(ClaimTypes.URI_BASE.toString());
        callbackHandler.setRoleAttributeName("role");

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
        for (Claim c : claims) {
            Assert.assertTrue("Invalid ClaimType URI: " + c.getClaimType(),
                              c.getClaimType().toString().equals(roleClaimType)
                              || c.getClaimType().equals(ClaimTypes.COUNTRY)
                              || c.getClaimType().equals(AbstractSAMLCallbackHandler.CLAIM_TYPE_LANGUAGE)
                              );
        }
    }




}
