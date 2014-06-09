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

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.EHCacheTokenReplayCache;
import org.apache.cxf.fediz.core.InMemoryTokenReplayCache;
import org.apache.cxf.fediz.core.TokenReplayCache;
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
import org.junit.AfterClass;
import org.junit.Assert;

public class FedizConfigurationTest {

    private static final String ISSUER = "http://url_to_the_issuer";
    private static final String PROTOCOL_VERSION = "1.0.0";
    //private static final String REQUEST = "request value";
    private static final String REPLY = "reply value";
    private static final String TARGET_REALM = "target realm";
    private static final String HOME_REALM_CLASS = "org.apache.fediz.realm.MyHomeRealm.class";
    private static final String FRESHNESS_VALUE = "10000";

    private static final String CONFIG_NAME = "ROOT";
    private static final String CLOCK_SKEW = "1000";

    private static final String KEYSTORE_PASSWORD_1 = "passw0rd1";
    private static final String KEYSTORE_RESOURCE_PATH_1 = "org.apache.fediz.kestore1";
    private static final String KEYSTORE_PASSWORD_2 = "passw0rd2";
    private static final String KEYSTORE_RESOURCE_PATH_2 = "org.apache.fediz.kestore2";
    private static final String KEYSTORE_PASSWORD_3 = "passw0rd3";
    private static final String KEYSTORE_RESOURCE_PATH_3 = "org.apache.fediz.kestore3";
    private static final String AUTH_TYPE_VALUE = "some auth type";

    private static final String AUDIENCE_URI_1 = "http://host_one:port/url";
    private static final String AUDIENCE_URI_2 = "http://host_two:port/url";
    private static final String AUDIENCE_URI_3 = "http://host_three:port/url";

    private static final String ROLE_DELIMITER = ";";
    private static final String ROLE_URI = "http://someserver:8080/path/roles.uri";
    private static final String CLAIM_TYPE_1 = "a particular claim type";
    private static final String CLAIM_TYPE_2 = "a second particular claim type";
    private static final String SUBJECT_VALUE_1 = ".*CN=www.sts1.com.*";
    private static final String SUBJECT_VALUE_2 = ".*CN=www.sts2.com.*";
    private static final String SUBJECT_VALUE_3 = ".*CN=www.sts3.com.*";
    

    private static final String CONFIG_FILE = "./target/fedizconfig.xml";
    
    @AfterClass
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }

    //CHECKSTYLE:OFF
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
        ks0.setPassword(KEYSTORE_PASSWORD_1);
        ks0.setResource(KEYSTORE_RESOURCE_PATH_1);
        tm0.setKeyStore(ks0);
        
        certStores.getTrustManager().add(tm0);
        
        TrustManagersType tm1 = new TrustManagersType();
        KeyStoreType ks1 = new KeyStoreType();
        ks1.setType("JKS");
        ks1.setPassword(KEYSTORE_PASSWORD_2);
        ks1.setResource(KEYSTORE_RESOURCE_PATH_2);
        tm1.setKeyStore(ks1);
        
        certStores.getTrustManager().add(tm1);
        
        TrustManagersType tm2 = new TrustManagersType();
        KeyStoreType ks2 = new KeyStoreType();
        ks2.setType("JKS");
        ks2.setPassword(KEYSTORE_PASSWORD_3);
        ks2.setResource(KEYSTORE_RESOURCE_PATH_3);
        tm2.setKeyStore(ks2);
        
        certStores.getTrustManager().add(tm2);
        
        config.setCertificateStores(certStores);
        
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        
        TrustedIssuerType ti0 = new TrustedIssuerType();
        ti0.setCertificateValidation(ValidationType.CHAIN_TRUST);
        ti0.setName("issuer1");
        ti0.setSubject(SUBJECT_VALUE_1);
        trustedIssuers.getIssuer().add(ti0);
        
        TrustedIssuerType ti1 = new TrustedIssuerType();
        ti1.setCertificateValidation(ValidationType.CHAIN_TRUST);
        ti1.setName("issuer1");
        ti1.setSubject(SUBJECT_VALUE_2);
        trustedIssuers.getIssuer().add(ti1);
        
        TrustedIssuerType ti2 = new TrustedIssuerType();
        ti2.setCertificateValidation(ValidationType.CHAIN_TRUST);
        ti2.setName("issuer1");
        ti2.setSubject(SUBJECT_VALUE_3);
        trustedIssuers.getIssuer().add(ti2);
        
        config.setTrustedIssuers(trustedIssuers);

        FederationProtocolType protocol = new FederationProtocolType();
        config.setProtocol(protocol);

        CallbackType authType = new CallbackType();
        authType.setType(ArgumentType.STRING);
        authType.setValue(AUTH_TYPE_VALUE);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(AUDIENCE_URI_1);
        audienceUris.getAudienceItem().add(AUDIENCE_URI_2);
        audienceUris.getAudienceItem().add(AUDIENCE_URI_3);
        config.setAudienceUris(audienceUris);

        protocol.setAuthenticationType(authType);
        protocol.setRoleDelimiter(ROLE_DELIMITER);
        protocol.setRoleURI(ROLE_URI);

        ClaimTypesRequested claimTypeReq = new ClaimTypesRequested();
        ClaimType claimType = new ClaimType();
        claimType.setOptional(true);
        claimType.setType(CLAIM_TYPE_1);
        claimTypeReq.getClaimType().add(claimType);

        ClaimType claimType2 = new ClaimType();
        claimType2.setOptional(true);
        claimType2.setType(CLAIM_TYPE_2);
        claimTypeReq.getClaimType().add(claimType2);

        protocol.setClaimTypesRequested(claimTypeReq);

        CallbackType freshness = new CallbackType();
        freshness.setValue(FRESHNESS_VALUE);
        protocol.setFreshness(freshness);

        CallbackType homeRealm = new CallbackType();
        homeRealm.setType(ArgumentType.CLASS);
        homeRealm.setValue(HOME_REALM_CLASS);
        protocol.setHomeRealm(homeRealm);

        CallbackType realm = new CallbackType();
        realm.setValue(TARGET_REALM);
        protocol.setRealm(realm);
        
        protocol.setReply(REPLY);
        protocol.setVersion(PROTOCOL_VERSION);
        
        CallbackType issuer = new CallbackType();
        issuer.setValue(ISSUER);
        protocol.setIssuer(issuer);

        return rootConfig;

    }

    @org.junit.Test
    public void readWriteConfig() throws JAXBException {

        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);
        FedizConfig configOut = createConfiguration();

        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        
        StringReader reader = new StringReader(writer.toString());
        jaxbContext.createUnmarshaller().unmarshal(reader);
    }

    @org.junit.Test
    public void testSaveAndLoadConfig() throws JAXBException, IOException {
        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        FedizConfig configOut = createConfiguration();
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        
        FederationConfigurator configurator = new FederationConfigurator();
        configurator.loadConfig(reader);

        File f = new File(CONFIG_FILE);
        f.createNewFile();

        configurator.saveConfiguration(f);
        
        configurator = new FederationConfigurator();
        f = new File(CONFIG_FILE);
        configurator.loadConfig(f);
    }

    @org.junit.Test
    public void verifyConfig() throws JAXBException {

        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        FederationConfigurator configurator = new FederationConfigurator();
        FedizConfig configOut = createConfiguration();
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        configurator.loadConfig(reader);

        ContextConfig config = configurator.getContextConfig(CONFIG_NAME);
        Assert.assertNotNull(config);
        AudienceUris audience = config.getAudienceUris();
        Assert.assertEquals(3, audience.getAudienceItem().size());
        Assert.assertTrue(config.getProtocol() instanceof FederationProtocolType);
        FederationProtocolType fp = (FederationProtocolType) config
                .getProtocol();

        Assert.assertEquals(HOME_REALM_CLASS, fp.getHomeRealm().getValue());

    }
    
    @org.junit.Test
    public void testTokenReplayCache() throws JAXBException, IOException {
        FedizConfig config = createConfiguration();
        
        // Test the default TokenReplayCache
        TokenReplayCache<String> defaultReplayCache = parseConfigAndReturnTokenReplayCache(config);
        Assert.assertNotNull(defaultReplayCache);
        Assert.assertTrue(defaultReplayCache instanceof EHCacheTokenReplayCache);
        
        // Now test setting another TokenReplayCache
        ContextConfig contextConfig = config.getContextConfig().get(0);
        contextConfig.setTokenReplayCache("org.apache.cxf.fediz.core.InMemoryTokenReplayCache");
        
        TokenReplayCache<String> newReplayCache = parseConfigAndReturnTokenReplayCache(config);
        Assert.assertNotNull(newReplayCache);
        Assert.assertTrue(newReplayCache instanceof InMemoryTokenReplayCache);
        
        // Now test setting another TokenReplayCache
        contextConfig.setTokenReplayCache("org.apache.cxf.fediz.core.EHCacheTokenReplayCache");
        
        newReplayCache = parseConfigAndReturnTokenReplayCache(config);
        Assert.assertNotNull(newReplayCache);
        Assert.assertTrue(newReplayCache instanceof EHCacheTokenReplayCache);
    }
    
    private TokenReplayCache<String> parseConfigAndReturnTokenReplayCache(FedizConfig config) 
        throws JAXBException {
        final JAXBContext jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(config, writer);
        StringReader reader = new StringReader(writer.toString());
        
        FederationConfigurator configurator = new FederationConfigurator();
        configurator.loadConfig(reader);

        FederationContext fedContext = configurator.getFederationContext(CONFIG_NAME);
        Assert.assertNotNull(fedContext);
        
        return fedContext.getTokenReplayCache();
    }

}