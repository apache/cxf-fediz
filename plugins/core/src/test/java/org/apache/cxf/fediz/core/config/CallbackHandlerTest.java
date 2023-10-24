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
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

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
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.SamlProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;
import org.apache.cxf.fediz.core.spi.HomeRealmCallback;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.spi.RealmCallback;
import org.apache.cxf.fediz.core.spi.ReplyCallback;
import org.apache.cxf.fediz.core.spi.SignInQueryCallback;
import org.apache.cxf.fediz.core.spi.WAuthCallback;
import org.apache.cxf.fediz.core.spi.WReqCallback;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;

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
    private static final String TEST_SIGNIN_QUERY = "pubid=myid";


    @AfterAll
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }

    private FedizConfig createConfiguration(boolean federation) throws JAXBException {

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

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(AUDIENCE_URI);
        config.setAudienceUris(audienceUris);

        final ProtocolType protocol;

        if (federation) {
            protocol = new FederationProtocolType();

            CallbackType freshness = new CallbackType();
            freshness.setValue(FRESHNESS_VALUE);
            ((FederationProtocolType)protocol).setFreshness(freshness);

            CallbackType realm = new CallbackType();
            realm.setValue(TARGET_REALM);
            protocol.setRealm(freshness);

            CallbackType reply = new CallbackType();
            reply.setValue(REPLY);
            ((FederationProtocolType)protocol).setReply(reply);
            ((FederationProtocolType)protocol).setVersion(PROTOCOL_VERSION);
        } else {
            protocol = new SamlProtocolType();
        }
        config.setProtocol(protocol);

        protocol.setRoleDelimiter(ROLE_DELIMITER);
        protocol.setRoleURI(ROLE_URI);

        ClaimTypesRequested claimTypeReq = new ClaimTypesRequested();
        ClaimType claimType = new ClaimType();
        claimType.setOptional(true);
        claimType.setType(CLAIM_TYPE);
        claimTypeReq.getClaimType().add(claimType);
        protocol.setClaimTypesRequested(claimTypeReq);

        return rootConfig;
    }

    private FedizConfig createConfigWithoutCB(boolean federation) throws JAXBException {

        FedizConfig config = createConfiguration(federation);
        ProtocolType protocol = config.getContextConfig().get(0).getProtocol();

        CallbackType issuer = new CallbackType();
        issuer.setType(ArgumentType.STRING);
        issuer.setValue(TestCallbackHandler.TEST_IDP);
        protocol.setIssuer(issuer);

        if (protocol instanceof FederationProtocolType) {
            CallbackType homeRealm = new CallbackType();
            homeRealm.setType(ArgumentType.STRING);
            homeRealm.setValue(TestCallbackHandler.TEST_HOME_REALM);
            ((FederationProtocolType)protocol).setHomeRealm(homeRealm);

            CallbackType authType = new CallbackType();
            authType.setType(ArgumentType.STRING);
            authType.setValue(TestCallbackHandler.TEST_WAUTH);
            ((FederationProtocolType)protocol).setAuthenticationType(authType);

            CallbackType tokenRequest = new CallbackType();
            tokenRequest.setType(ArgumentType.STRING);
            tokenRequest.setValue(TestCallbackHandler.TEST_WREQ);
            ((FederationProtocolType)protocol).setRequest(tokenRequest);
        }

        CallbackType signInQueryType = new CallbackType();
        signInQueryType.setType(ArgumentType.STRING);
        signInQueryType.setValue(TEST_SIGNIN_QUERY);
        protocol.setSignInQuery(signInQueryType);

        return config;
    }

    private FedizConfig createConfigCB(boolean federation) throws JAXBException {

        FedizConfig config = createConfiguration(federation);
        ProtocolType protocol = config.getContextConfig().get(0).getProtocol();

        CallbackType realmType = new CallbackType();
        realmType.setType(ArgumentType.CLASS);
        realmType.setValue(CALLBACKHANDLER_CLASS);
        protocol.setRealm(realmType);

        CallbackType issuer = new CallbackType();
        issuer.setType(ArgumentType.CLASS);
        issuer.setValue(CALLBACKHANDLER_CLASS);
        protocol.setIssuer(issuer);

        if (protocol instanceof FederationProtocolType) {
            CallbackType homeRealm = new CallbackType();
            homeRealm.setType(ArgumentType.CLASS);
            homeRealm.setValue(CALLBACKHANDLER_CLASS);
            ((FederationProtocolType)protocol).setHomeRealm(homeRealm);

            CallbackType authType = new CallbackType();
            authType.setType(ArgumentType.CLASS);
            authType.setValue(CALLBACKHANDLER_CLASS);
            ((FederationProtocolType)protocol).setAuthenticationType(authType);

            CallbackType tokenRequest = new CallbackType();
            tokenRequest.setType(ArgumentType.CLASS);
            tokenRequest.setValue(CALLBACKHANDLER_CLASS);
            ((FederationProtocolType)protocol).setRequest(tokenRequest);

            CallbackType replyType = new CallbackType();
            replyType.setType(ArgumentType.CLASS);
            replyType.setValue(CALLBACKHANDLER_CLASS);
            ((FederationProtocolType)protocol).setReply(replyType);
        }

        CallbackType signInQueryType = new CallbackType();
        signInQueryType.setType(ArgumentType.CLASS);
        signInQueryType.setValue(CALLBACKHANDLER_CLASS);
        protocol.setSignInQuery(signInQueryType);

        return config;
    }

    @org.junit.jupiter.api.Test
    public void testParamsWithCallbackHandlerFederation() throws Exception {

        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        FedizConfig configOut = createConfigCB(true);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());

        FedizConfigurator configurator = new FedizConfigurator();
        configurator.loadConfig(reader);

        FedizContext ctx = configurator.getFedizContext(CONFIG_NAME);

        FederationProtocol fp = (FederationProtocol)ctx.getProtocol();

        Object issuerObj = fp.getIssuer();
        Assertions.assertTrue(issuerObj instanceof CallbackHandler);
        CallbackHandler issuerCB = (CallbackHandler)issuerObj;
        IDPCallback callbackIDP = new IDPCallback(null);
        issuerCB.handle(new Callback[] {callbackIDP});
        String issuerURL = callbackIDP.getIssuerUrl().toString();
        Assertions.assertEquals(TestCallbackHandler.TEST_IDP, issuerURL);

        Object wAuthObj = fp.getAuthenticationType();
        Assertions.assertTrue(wAuthObj instanceof CallbackHandler);
        CallbackHandler wauthCB = (CallbackHandler)wAuthObj;
        WAuthCallback callbackWA = new WAuthCallback(null);
        wauthCB.handle(new Callback[] {callbackWA});
        String wAuth = callbackWA.getWauth();
        Assertions.assertEquals(TestCallbackHandler.TEST_WAUTH, wAuth);

        Object wReqObj = fp.getRequest();
        Assertions.assertTrue(wReqObj instanceof CallbackHandler);
        CallbackHandler wreqCB = (CallbackHandler)wReqObj;
        WReqCallback callbackReq = new WReqCallback(null);
        wreqCB.handle(new Callback[] {callbackReq});
        String wReq = callbackReq.getWreq();
        Assertions.assertEquals(TestCallbackHandler.TEST_WREQ, wReq);

        Object homeRealmObj = fp.getHomeRealm();
        Assertions.assertTrue(homeRealmObj instanceof CallbackHandler);
        CallbackHandler hrCB = (CallbackHandler)homeRealmObj;
        HomeRealmCallback callbackHR = new HomeRealmCallback(null);
        hrCB.handle(new Callback[] {callbackHR});
        String hr = callbackHR.getHomeRealm();
        Assertions.assertEquals(TestCallbackHandler.TEST_HOME_REALM, hr);

        Object wtRealmObj = fp.getRealm();
        Assertions.assertTrue(wtRealmObj instanceof CallbackHandler);
        CallbackHandler wtrCB = (CallbackHandler)wtRealmObj;
        RealmCallback callbackWTR = new RealmCallback(null);
        wtrCB.handle(new Callback[]{callbackWTR});
        String wtr = callbackWTR.getRealm();
        Assertions.assertEquals(TestCallbackHandler.TEST_WTREALM, wtr);

        Object signInQueryObj = fp.getSignInQuery();
        Assertions.assertTrue(signInQueryObj instanceof CallbackHandler);
        CallbackHandler siqCB = (CallbackHandler)signInQueryObj;
        SignInQueryCallback callbackSIQ = new SignInQueryCallback(null);
        siqCB.handle(new Callback[] {callbackSIQ});
        Map<String, String> signinQueryMap = callbackSIQ.getSignInQueryParamMap();
        Assertions.assertEquals(2, signinQueryMap.size());
        Assertions.assertEquals("myid", signinQueryMap.get("pubid"));
        Assertions.assertEquals("<=>", signinQueryMap.get("testenc"));

        Object replyObj = fp.getReply();
        Assertions.assertTrue(replyObj instanceof CallbackHandler);
        CallbackHandler replyCB = (CallbackHandler)replyObj;
        ReplyCallback callbackReply = new ReplyCallback(null);
        replyCB.handle(new Callback[] {callbackReply});
        String reply = callbackReply.getReply();
        Assertions.assertEquals(TestCallbackHandler.TEST_REPLY, reply);

    }

    @org.junit.jupiter.api.Test
    public void testParamsWithCallbackHandlerSAML() throws Exception {

        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        FedizConfig configOut = createConfigCB(false);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());

        FedizConfigurator configurator = new FedizConfigurator();
        configurator.loadConfig(reader);

        FedizContext ctx = configurator.getFedizContext(CONFIG_NAME);

        SAMLProtocol protocol = (SAMLProtocol)ctx.getProtocol();

        Object issuerObj = protocol.getIssuer();
        Assertions.assertTrue(issuerObj instanceof CallbackHandler);
        CallbackHandler issuerCB = (CallbackHandler)issuerObj;
        IDPCallback callbackIDP = new IDPCallback(null);
        issuerCB.handle(new Callback[] {callbackIDP});
        String issuerURL = callbackIDP.getIssuerUrl().toString();
        Assertions.assertEquals(TestCallbackHandler.TEST_IDP, issuerURL);

        Object signInQueryObj = protocol.getSignInQuery();
        Assertions.assertTrue(signInQueryObj instanceof CallbackHandler);
        CallbackHandler siqCB = (CallbackHandler)signInQueryObj;
        SignInQueryCallback callbackSIQ = new SignInQueryCallback(null);
        siqCB.handle(new Callback[] {callbackSIQ});
        Map<String, String> signinQueryMap = callbackSIQ.getSignInQueryParamMap();
        Assertions.assertEquals(2, signinQueryMap.size());
        Assertions.assertEquals("myid", signinQueryMap.get("pubid"));
        Assertions.assertEquals("<=>", signinQueryMap.get("testenc"));
    }

    @org.junit.jupiter.api.Test
    public void testParamsWithoutCallbackHandlerFederation() throws Exception {

        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        FedizConfig configOut = createConfigWithoutCB(true);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());

        FedizConfigurator configurator = new FedizConfigurator();
        configurator.loadConfig(reader);

        FedizContext ctx = configurator.getFedizContext(CONFIG_NAME);

        FederationProtocol fp = (FederationProtocol)ctx.getProtocol();

        Object issuerObj = fp.getIssuer();
        Assertions.assertTrue(issuerObj instanceof String);
        String issuerURL = (String)issuerObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_IDP, issuerURL);

        Object wAuthObj = fp.getAuthenticationType();
        Assertions.assertTrue(wAuthObj instanceof String);
        String wAuth = (String)wAuthObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_WAUTH, wAuth);

        Object wReqObj = fp.getRequest();
        Assertions.assertTrue(wReqObj instanceof String);
        String wReq = (String)wReqObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_WREQ, wReq);

        Object homeRealmObj = fp.getHomeRealm();
        Assertions.assertTrue(homeRealmObj instanceof String);
        String hr = (String)homeRealmObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_HOME_REALM, hr);

        Object signInQueryObj = fp.getSignInQuery();
        Assertions.assertTrue(signInQueryObj instanceof String);
        String signInQuery = (String)signInQueryObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_SIGNIN_QUERY, signInQuery);
    }

    @org.junit.jupiter.api.Test
    public void testParamsWithoutCallbackHandlerSAML() throws Exception {

        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        FedizConfig configOut = createConfigWithoutCB(false);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());

        FedizConfigurator configurator = new FedizConfigurator();
        configurator.loadConfig(reader);

        FedizContext ctx = configurator.getFedizContext(CONFIG_NAME);

        Protocol protocol = ctx.getProtocol();

        Object issuerObj = protocol.getIssuer();
        Assertions.assertTrue(issuerObj instanceof String);
        String issuerURL = (String)issuerObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_IDP, issuerURL);

        Object signInQueryObj = protocol.getSignInQuery();
        Assertions.assertTrue(signInQueryObj instanceof String);
        String signInQuery = (String)signInQueryObj;
        Assertions.assertEquals(TestCallbackHandler.TEST_SIGNIN_QUERY, signInQuery);
    }


}
