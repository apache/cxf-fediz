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

package org.apache.cxf.fediz.core.config;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import junit.framework.Assert;

import org.apache.cxf.fediz.common.SecurityTestUtil;
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
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;
import org.apache.cxf.fediz.core.spi.HomeRealmCallback;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.spi.WAuthCallback;
import org.junit.AfterClass;

public class CallbackHandlerTest {

    private static final String PROTOCOL_VERSION = "1.0.0";
    private static final String REPLY = "reply value";
    private static final String TARGET_REALM = "target realm";
    private static final String CALLBACKHANDLER_CLASS = "org.apache.cxf.fediz.core.config.TestCallbackHandler";
    private static final String FRESHNESS_VALUE = "10000";
    private static final String CONFIG_NAME = "ROOT";
    private static final String CLOCK_SKEW = "1000";
    private static final String KEYSTORE_PASSWORD = "passw0rd1";
    private static final String KEYSTORE_RESOURCE_PATH = "org.apache.fediz.kestore1";
    private static final String AUDIENCE_URI = "http://host_one:port/url";
    
    private static final String ROLE_DELIMITER = ";";
    private static final String ROLE_URI = "http://someserver:8080/path/roles.uri";
    private static final String CLAIM_TYPE = "a particular claim type";
    private static final String SUBJECT_VALUE = ".*CN=www.sts1.com.*";
    
    
    @AfterClass
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }
    
    private FedizConfig createConfiguration() throws JAXBException {

        FedizConfig rootConfig = new FedizConfig();
        ContextConfig config = new ContextConfig();
        rootConfig.getContextConfig().add(config);

        config.setName(CONFIG_NAME);
        config.setMaximumClockSkew(new BigInteger(CLOCK_SKEW));

        CertificateStores certStores = new CertificateStores();
        
        TrustManagersType tm0 = new TrustManagersType();       
        KeyStoreType ks0 = new KeyStoreType();
        ks0.setType("JKS");
        ks0.setPassword(KEYSTORE_PASSWORD);
        ks0.setResource(KEYSTORE_RESOURCE_PATH);
        tm0.setKeyStore(ks0);
        certStores.getTrustManager().add(tm0);    
        config.setCertificateStores(certStores);
        
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        TrustedIssuerType ti0 = new TrustedIssuerType();
        ti0.setCertificateValidation(ValidationType.CHAIN_TRUST);
        ti0.setName("issuer1");
        ti0.setSubject(SUBJECT_VALUE);
        trustedIssuers.getIssuer().add(ti0);
        config.setTrustedIssuers(trustedIssuers);

        FederationProtocolType protocol = new FederationProtocolType();
        config.setProtocol(protocol);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(AUDIENCE_URI);
        config.setAudienceUris(audienceUris);

        protocol.setRoleDelimiter(ROLE_DELIMITER);
        protocol.setRoleURI(ROLE_URI);

        ClaimTypesRequested claimTypeReq = new ClaimTypesRequested();
        ClaimType claimType = new ClaimType();
        claimType.setOptional(true);
        claimType.setType(CLAIM_TYPE);
        claimTypeReq.getClaimType().add(claimType);
        protocol.setClaimTypesRequested(claimTypeReq);
        
        CallbackType freshness = new CallbackType();
        freshness.setValue(FRESHNESS_VALUE);
        protocol.setFreshness(freshness);
        
        protocol.setRealm(TARGET_REALM);
        protocol.setReply(REPLY);
        protocol.setRequest("REQUEST");
        protocol.setVersion(PROTOCOL_VERSION);

        return rootConfig;
    }
    
    private FedizConfig createConfigWithoutCB() throws JAXBException {
        
        FedizConfig config = createConfiguration();
        FederationProtocolType protocol = (FederationProtocolType)config.getContextConfig().get(0).getProtocol();
        
        CallbackType homeRealm = new CallbackType();
        homeRealm.setType(ArgumentType.STRING);
        homeRealm.setValue(TestCallbackHandler.TEST_HOME_REALM);
        protocol.setHomeRealm(homeRealm);
        
        CallbackType issuer = new CallbackType();
        issuer.setType(ArgumentType.STRING);
        issuer.setValue(TestCallbackHandler.TEST_IDP);
        protocol.setIssuer(issuer);
        
        CallbackType authType = new CallbackType();
        authType.setType(ArgumentType.STRING);
        authType.setValue(TestCallbackHandler.TEST_WAUTH);
        protocol.setAuthenticationType(authType);
        
        return config;
    }
    
    private FedizConfig createConfigCB() throws JAXBException {
        
        FedizConfig config = createConfiguration();
        FederationProtocolType protocol = (FederationProtocolType)config.getContextConfig().get(0).getProtocol();
        
        CallbackType homeRealm = new CallbackType();
        homeRealm.setType(ArgumentType.CLASS);
        homeRealm.setValue(CALLBACKHANDLER_CLASS);
        protocol.setHomeRealm(homeRealm);
        
        CallbackType issuer = new CallbackType();
        issuer.setType(ArgumentType.CLASS);
        issuer.setValue(CALLBACKHANDLER_CLASS);
        protocol.setIssuer(issuer);
        
        CallbackType authType = new CallbackType();
        authType.setType(ArgumentType.CLASS);
        authType.setValue(CALLBACKHANDLER_CLASS);
        protocol.setAuthenticationType(authType);
        
        return config;
    }
    
    @org.junit.Test
    public void testParamsWithCallbackHandler() throws Exception {
        
        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        FedizConfig configOut = createConfigCB();
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        
        FederationConfigurator configurator = new FederationConfigurator();
        configurator.loadConfig(reader);
        
        FederationContext ctx = configurator.getFederationContext(CONFIG_NAME);
        
        FederationProtocol fp = (FederationProtocol)ctx.getProtocol();
        
        Object issuerObj = fp.getIssuer();
        Assert.assertTrue(issuerObj instanceof CallbackHandler);
        CallbackHandler issuerCB = (CallbackHandler)issuerObj;
        IDPCallback callbackIDP = new IDPCallback(null);
        issuerCB.handle(new Callback[] {callbackIDP});
        String issuerURL = callbackIDP.getIssuerUrl().toString();
        Assert.assertEquals(TestCallbackHandler.TEST_IDP, issuerURL);
        
        Object wAuthObj = fp.getAuthenticationType();
        Assert.assertTrue(wAuthObj instanceof CallbackHandler);
        CallbackHandler wauthCB = (CallbackHandler)wAuthObj;
        WAuthCallback callbackWA = new WAuthCallback(null);
        wauthCB.handle(new Callback[] {callbackWA});
        String wAuth = callbackWA.getWauth();
        Assert.assertEquals(TestCallbackHandler.TEST_WAUTH, wAuth);
        
        Object homeRealmObj = fp.getHomeRealm();
        Assert.assertTrue(homeRealmObj instanceof CallbackHandler);
        CallbackHandler hrCB = (CallbackHandler)homeRealmObj;
        HomeRealmCallback callbackHR = new HomeRealmCallback(null);
        hrCB.handle(new Callback[] {callbackHR});
        String hr = callbackHR.getHomeRealm();
        Assert.assertEquals(TestCallbackHandler.TEST_HOME_REALM, hr);
    }
    
    @org.junit.Test
    public void testParamsWithoutCallbackHandler() throws Exception {
        
        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        FedizConfig configOut = createConfigWithoutCB();
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        
        FederationConfigurator configurator = new FederationConfigurator();
        configurator.loadConfig(reader);
        
        FederationContext ctx = configurator.getFederationContext(CONFIG_NAME);
        
        FederationProtocol fp = (FederationProtocol)ctx.getProtocol();
        
        Object issuerObj = fp.getIssuer();
        Assert.assertTrue(issuerObj instanceof String);
        String issuerURL = (String)issuerObj;
        Assert.assertEquals(TestCallbackHandler.TEST_IDP, issuerURL);
        
        Object wAuthObj = fp.getAuthenticationType();
        Assert.assertTrue(wAuthObj instanceof String);
        String wAuth = (String)wAuthObj;
        Assert.assertEquals(TestCallbackHandler.TEST_WAUTH, wAuth);
        
        Object homeRealmObj = fp.getHomeRealm();
        Assert.assertTrue(homeRealmObj instanceof String);
        String hr = (String)homeRealmObj;
        Assert.assertEquals(TestCallbackHandler.TEST_HOME_REALM, hr);
    }
    
}
