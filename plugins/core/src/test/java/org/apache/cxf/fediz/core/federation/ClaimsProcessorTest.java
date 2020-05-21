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

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.xml.sax.SAXException;

import org.apache.cxf.fediz.common.STSUtil;
import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.KeystoreCallbackHandler;
import org.apache.cxf.fediz.core.SAML2CallbackHandler;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;
import org.apache.cxf.fediz.core.config.jaxb.AudienceUris;
import org.apache.cxf.fediz.core.config.jaxb.CallbackType;
import org.apache.cxf.fediz.core.config.jaxb.CertificateStores;
import org.apache.cxf.fediz.core.config.jaxb.ClaimType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimTypesRequested;
import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.FedizConfig;
import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;
import org.apache.cxf.fediz.core.exception.ProcessingException;
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
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.XMLUtils;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * Test for claim transformations with ClaimsProcessor
 */
public class ClaimsProcessorTest {

    private static final String ISSUER = "FedizSTSIssuer";
    private static final String PROTOCOL_VERSION = "1.0.0";
    //private static final String REQUEST = "request value";
    private static final String REPLY = "reply value";
    private static final String TARGET_REALM = "target realm";
    private static final String FRESHNESS_VALUE = "10000";

    private static final String CONFIG_NAME = "ROOT";
    private static final String CLOCK_SKEW = "1000";

    private static final String AUTH_TYPE_VALUE = "some auth type";

    private static final String AUDIENCE_URI_1 = "http://host_one:port/url";

    private static final String ROLE_DELIMITER = ";";
    private static final String ROLE_URI = "http://someserver:8080/path/roles.uri";
    
    private static final String COPY_CLAIMS_PROCESSOR_CLASS = "org.apache.cxf.fediz.common.ClaimCopyProcessor";
    private static final String MUTATE_CLAIMS_PROCESSOR_CLASS = "org.apache.cxf.fediz.common.ClaimMutateProcessor";

    private static Crypto crypto;
    private static CallbackHandler cbPasswordHandler = new KeystoreCallbackHandler();

    @BeforeClass
    public static void init() {
        try {
            crypto = CryptoFactory.getInstance("signature.properties");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @AfterClass
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }

    //CHECKSTYLE:OFF
    private FedizConfig createConfiguration(String claimsProcessorClass) throws JAXBException {

        FedizConfig rootConfig = new FedizConfig();
        ContextConfig config = new ContextConfig();
        rootConfig.getContextConfig().add(config);

        config.setName(CONFIG_NAME);
        config.setMaximumClockSkew(new BigInteger(CLOCK_SKEW));

        CertificateStores certStores = new CertificateStores();

        TrustManagersType tm0 = new TrustManagersType();
        KeyStoreType ks0 = new KeyStoreType();
        ks0.setType("JKS");
        ks0.setPassword("storepass");
        ks0.setResource("ststrust.jks");
        tm0.setKeyStore(ks0);

        certStores.getTrustManager().add(tm0);

        config.setCertificateStores(certStores);

        TrustedIssuers trustedIssuers = new TrustedIssuers();

        TrustedIssuerType ti0 = new TrustedIssuerType();
        ti0.setCertificateValidation(ValidationType.PEER_TRUST);
        trustedIssuers.getIssuer().add(ti0);

        config.setTrustedIssuers(trustedIssuers);

        ProtocolType protocol = new FederationProtocolType();

        CallbackType authType = new CallbackType();
        authType.setType(ArgumentType.STRING);
        authType.setValue(AUTH_TYPE_VALUE);
        ((FederationProtocolType)protocol).setAuthenticationType(authType);

        CallbackType freshness = new CallbackType();
        freshness.setValue(FRESHNESS_VALUE);
        ((FederationProtocolType)protocol).setFreshness(freshness);

        CallbackType reply = new CallbackType();
        reply.setValue(REPLY);
        ((FederationProtocolType)protocol).setReply(reply);
        ((FederationProtocolType)protocol).setVersion(PROTOCOL_VERSION);

        config.setProtocol(protocol);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(AUDIENCE_URI_1);
        config.setAudienceUris(audienceUris);

        protocol.setRoleDelimiter(ROLE_DELIMITER);
        protocol.setRoleURI(ROLE_URI);

        ClaimTypesRequested claimTypeReq = new ClaimTypesRequested();
        ClaimType claimType = new ClaimType();
        claimType.setOptional(true);
        claimType.setType(ClaimTypes.FIRSTNAME.toString());
        claimTypeReq.getClaimType().add(claimType);

        ClaimType claimType2 = new ClaimType();
        claimType2.setOptional(true);
        claimType2.setType(ClaimTypes.LASTNAME.toString());
        claimTypeReq.getClaimType().add(claimType2);

        protocol.setClaimTypesRequested(claimTypeReq);

        CallbackType realm = new CallbackType();
        realm.setValue(TARGET_REALM);
        protocol.setRealm(realm);

        CallbackType issuer = new CallbackType();
        issuer.setValue(ISSUER);
        protocol.setIssuer(issuer);
        
        if (claimsProcessorClass != null) {
            CallbackType cpc = new CallbackType();
            cpc.setType(ArgumentType.CLASS);
            cpc.setValue(claimsProcessorClass);
            config.setClaimsProcessor(cpc);
        }

        return rootConfig;

    }

    @org.junit.Test
    public void testWithoutCustomClaimProcessor() throws Exception {
        String originalClaimValue = "Alice";
        String claimsProcessorClass = null;
        
        FedizResponse wfRes = performLogin(ClaimTypes.FIRSTNAME.toString(), originalClaimValue, claimsProcessorClass);

        Object claimValue = null;
        for (Claim c : wfRes.getClaims()) {
            if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                claimValue = c.getValue();
            }
        }

        Assert.assertEquals(originalClaimValue, claimValue);
    }
    
    @org.junit.Test
    public void testCustomClaimProcessor() throws Exception {
        String originalClaimValue = "Alice";
        String claimsProcessorClass = COPY_CLAIMS_PROCESSOR_CLASS;
        
        FedizResponse wfRes = performLogin(ClaimTypes.FIRSTNAME.toString(), originalClaimValue, claimsProcessorClass);

        Object claimValue = null;
        for (Claim c : wfRes.getClaims()) {
            if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                claimValue = c.getValue();
            }
        }

        Assert.assertEquals(originalClaimValue, claimValue);
    }
    
    @org.junit.Test
    public void testClaimModificationProcessor() throws Exception {
        String originalClaimValue = "Alice";
        String claimsProcessorClass = MUTATE_CLAIMS_PROCESSOR_CLASS;
        
        FedizResponse wfRes =
            performLogin(ClaimTypes.PRIVATE_PERSONAL_IDENTIFIER.toString(), originalClaimValue, claimsProcessorClass);

        Object firstname = null;
        Object lastname = null;
        
        Assert.assertEquals(2, wfRes.getClaims().size());
        
        for (Claim c : wfRes.getClaims()) {
            if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                firstname = c.getValue();
            } else if (ClaimTypes.LASTNAME.equals(c.getClaimType())) {
                lastname = c.getValue();
            }
        }

        Assert.assertEquals("alice", firstname);
        Assert.assertEquals("ALICE", lastname);
    }

    private FedizResponse performLogin(String claimType, String claimValue, String claimsProcessorClass)
        throws WSSecurityException, IOException, UnsupportedCallbackException, JAXBException, ProcessingException,
        SAXException, ParserConfigurationException {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer(ISSUER);
        callbackHandler.setSubjectName("alice");
        callbackHandler.setAttributeNameFormat(ClaimTypes.URI_BASE.toString());
        callbackHandler.setCustomClaimName(claimType);
        callbackHandler.setCustomAttributeValues(Collections.singletonList(claimValue));

        ConditionsBean cp = new ConditionsBean();
        AudienceRestrictionBean audienceRestriction = new AudienceRestrictionBean();
        audienceRestriction.getAudienceURIs().add(AUDIENCE_URI_1);
        cp.setAudienceRestrictions(Collections.singletonList(audienceRestriction));
        callbackHandler.setConditions(cp);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        String rstr = createSamlToken(assertion, "mystskey", true);

        FedizRequest wfReq = new FedizRequest();
        wfReq.setAction(FederationConstants.ACTION_SIGNIN);
        wfReq.setResponseToken(rstr);

        FedizConfig config = createConfiguration(claimsProcessorClass);
        StringWriter writer = new StringWriter();
        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        jaxbContext.createMarshaller().marshal(config, writer);
        StringReader reader = new StringReader(writer.toString());

        FedizConfigurator configurator = new FedizConfigurator();
        configurator.loadConfig(reader);
        FedizContext context = configurator.getFedizContext(CONFIG_NAME);

        FedizProcessor wfProc = new FederationProcessorImpl();
        return wfProc.processRequest(wfReq, context);
    }

    private String createSamlToken(SamlAssertionWrapper assertion, String alias, boolean sign)
        throws IOException, UnsupportedCallbackException, WSSecurityException, SAXException,
        ParserConfigurationException {
        return createSamlToken(assertion, alias, sign, STSUtil.SAMPLE_RSTR_COLL_MSG);
    }

    private String createSamlToken(SamlAssertionWrapper assertion, String alias, boolean sign, String rstr)
        throws IOException, UnsupportedCallbackException, WSSecurityException, SAXException,
        ParserConfigurationException {
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
