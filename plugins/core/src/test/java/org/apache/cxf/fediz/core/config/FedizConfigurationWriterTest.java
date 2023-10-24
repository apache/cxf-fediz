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
import java.util.List;

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
import org.apache.cxf.fediz.core.config.jaxb.KeyManagersType;
import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.SamlProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.TokenValidators;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;

public class FedizConfigurationWriterTest {

    private static final String TRUST_ISSUER_CERT_CONSTRAINT = ".*CN=www.sts.com.*";
    private static final String TRUST_ISSUER_NAME = "Apache FEDIZ IDP";
    private static final String ROLE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role";
    private static final String ROLE_DELIMITER = ";";

    private static final String ISSUER = "http://url_to_the_issuer";
    private static final String PROTOCOL_VERSION = "1.0.0";
    private static final String REPLY = "reply value";
    private static final String TARGET_REALM = "target realm";
    private static final String HOME_REALM_CLASS = "org.apache.fediz.realm.MyHomeRealm.class";
    private static final String FRESHNESS_VALUE = "10000";

    private static final String CONFIG_NAME = "ROOT";
    private static final String CLOCK_SKEW = "1000";
    private static final String KEYSTORE_FILE = "ststrust.jks";

    private static final String JKS_TYPE = "JKS";

    private static final String KEYSTORE_PASSWORD = "storepass";
    private static final String KEY_PASSWORD = "stskpass";
    private static final String KEY_ALIAS = "mystskey";

    private static final String AUDIENCE_URI_1 = "http://host_one:port/url";

    private static final String AUTH_TYPE_VALUE = "some auth type";

    private static final String CLAIM_TYPE_1 = "a particular claim type";
    private static final String CLAIM_TYPE_2 = "another claim type";

    private static final String CONFIG_FILE = "./target/fediz_test_config.xml";

    private static final String TEST_WREQ =
        "<RequestSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
        + "<t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</t:TokenType>"
        + "</RequestSecurityToken>";



    @AfterAll
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }

    //CHECKSTYLE:OFF
    private FedizConfig createConfiguration(boolean federation) throws JAXBException {

        FedizConfig rootConfig = new FedizConfig();
        ContextConfig config = new ContextConfig();
        rootConfig.getContextConfig().add(config);

        config.setName(CONFIG_NAME);
        config.setMaximumClockSkew(new BigInteger(CLOCK_SKEW));

        KeyManagersType sigManager = new KeyManagersType();
        sigManager.setKeyPassword(KEY_PASSWORD);
        sigManager.setKeyAlias(KEY_ALIAS);

        KeyStoreType sigStore = new KeyStoreType();
        sigStore.setType(JKS_TYPE);
        sigStore.setPassword(KEYSTORE_PASSWORD);//integrity password
        sigStore.setFile(KEYSTORE_FILE);
        sigManager.setKeyStore(sigStore);

        config.setSigningKey(sigManager);

        TrustedIssuers trustedIssuers = new TrustedIssuers();

        TrustedIssuerType trustedIssuer = new TrustedIssuerType();
        trustedIssuer.setCertificateValidation(ValidationType.CHAIN_TRUST);
        trustedIssuer.setName(TRUST_ISSUER_NAME);
        trustedIssuer.setSubject(TRUST_ISSUER_CERT_CONSTRAINT);
        trustedIssuers.getIssuer().add(trustedIssuer);
        config.setTrustedIssuers(trustedIssuers);

        CertificateStores certStores = new CertificateStores();
        TrustManagersType truststore = new TrustManagersType();

        KeyStoreType ks1 = new KeyStoreType();
        ks1.setType(JKS_TYPE);
        ks1.setPassword(KEYSTORE_PASSWORD);
        ks1.setFile(KEYSTORE_FILE);
        truststore.setKeyStore(ks1);
        certStores.getTrustManager().add(truststore);
        config.setCertificateStores(certStores);

        CallbackType authType = new CallbackType();
        authType.setType(ArgumentType.STRING);
        authType.setValue(AUTH_TYPE_VALUE);

        CallbackType tokenRequest = new CallbackType();
        tokenRequest.setType(ArgumentType.STRING);
        tokenRequest.setValue(TEST_WREQ);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(AUDIENCE_URI_1);
        config.setAudienceUris(audienceUris);

        final ProtocolType protocol;

        if (federation) {
            protocol = new FederationProtocolType();

            ((FederationProtocolType)protocol).setAuthenticationType(authType);
            ((FederationProtocolType)protocol).setRequest(tokenRequest);

            CallbackType freshness = new CallbackType();
            freshness.setValue(FRESHNESS_VALUE);
            ((FederationProtocolType)protocol).setFreshness(freshness);

            CallbackType homeRealm = new CallbackType();
            homeRealm.setType(ArgumentType.CLASS);
            homeRealm.setValue(HOME_REALM_CLASS);
            ((FederationProtocolType)protocol).setHomeRealm(homeRealm);

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
        claimType.setType(CLAIM_TYPE_1);
        claimTypeReq.getClaimType().add(claimType);
        ClaimType claimType2 = new ClaimType();
        claimType2.setOptional(true);
        claimType2.setType(CLAIM_TYPE_2);
        claimTypeReq.getClaimType().add(claimType2);

        protocol.setClaimTypesRequested(claimTypeReq);

        CallbackType realm = new CallbackType();
        realm.setValue(TARGET_REALM);
        protocol.setRealm(realm);

        CallbackType issuer = new CallbackType();
        issuer.setValue(ISSUER);
        protocol.setIssuer(issuer);

        TokenValidators x = new TokenValidators();
        x.getValidator().add("org.apache.cxf.fediz.CustomValidator");
        x.getValidator().add("org.apache.cxf.fediz.core.NonexistentCustomValidator");
        protocol.setTokenValidators(x);

        return rootConfig;

    }

    @org.junit.jupiter.api.Test
    public void readWriteConfigFederation() throws JAXBException {

        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);
        FedizConfig configOut = createConfiguration(true);

        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);

        StringReader reader = new StringReader(writer.toString());
        jaxbContext.createUnmarshaller().unmarshal(reader);
    }

    @org.junit.jupiter.api.Test
    public void readWriteConfigSAML() throws JAXBException {

        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);
        FedizConfig configOut = createConfiguration(false);

        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);

        StringReader reader = new StringReader(writer.toString());
        jaxbContext.createUnmarshaller().unmarshal(reader);
    }

    @org.junit.jupiter.api.Test
    public void testSaveAndLoadConfigFederation() throws JAXBException, IOException {
        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        FedizConfigurator configurator = new FedizConfigurator();
        FedizConfig configOut = createConfiguration(true);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        configurator.loadConfig(reader);

        File f = new File(CONFIG_FILE);
        f.createNewFile();

        configurator.saveConfiguration(f);

        configurator = new FedizConfigurator();
        f = new File(CONFIG_FILE);
        configurator.loadConfig(f);
    }

    @org.junit.jupiter.api.Test
    public void testSaveAndLoadConfigSAML() throws JAXBException, IOException {
        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        FedizConfigurator configurator = new FedizConfigurator();
        FedizConfig configOut = createConfiguration(false);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        configurator.loadConfig(reader);

        File f = new File(CONFIG_FILE);
        f.createNewFile();

        configurator.saveConfiguration(f);

        configurator = new FedizConfigurator();
        f = new File(CONFIG_FILE);
        configurator.loadConfig(f);
    }

    @org.junit.jupiter.api.Test
    public void verifyConfigFederation() throws JAXBException {

        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        /**
         * Test JAXB part
         */

        FedizConfigurator configurator = new FedizConfigurator();
        FedizConfig configOut = createConfiguration(true);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        configurator.loadConfig(reader);

        ContextConfig config = configurator.getContextConfig(CONFIG_NAME);
        Assertions.assertNotNull(config);
        AudienceUris audience = config.getAudienceUris();
        Assertions.assertEquals(1, audience.getAudienceItem().size());
        Assertions.assertTrue(config.getProtocol() instanceof FederationProtocolType);
        FederationProtocolType fp = (FederationProtocolType)config.getProtocol();

        Assertions.assertEquals(HOME_REALM_CLASS, fp.getHomeRealm().getValue());
        //Assertions.assertEquals(config.getCertificateValidation(),ValidationType.CHAIN_TRUST);

        /**
         * Check Runtime configuration
         */
        FedizContext fedContext = configurator.getFedizContext(CONFIG_NAME);
        Protocol protocol = fedContext.getProtocol();
        Assertions.assertTrue(protocol instanceof FederationProtocol);
        FederationProtocol fedProtocol = (FederationProtocol) protocol;
        Assertions.assertEquals(TARGET_REALM, fedProtocol.getRealm());

        Object auth = fedProtocol.getAuthenticationType();
        Assertions.assertTrue(auth instanceof String);
        Assertions.assertEquals((String)auth, AUTH_TYPE_VALUE);

        Object wreq = fedProtocol.getRequest();
        Assertions.assertTrue(wreq instanceof String);
        Assertions.assertEquals((String)wreq, TEST_WREQ);

        //Assertions.assertEquals(ValidationMethod.CHAIN_TRUST, fedContext.getCertificateValidation());
        List<String> audienceUris = fedContext.getAudienceUris();
        Assertions.assertEquals(1, audienceUris.size());
        List<TrustedIssuer> trustedIssuers = fedContext.getTrustedIssuers();
        Assertions.assertEquals(1, trustedIssuers.size());
        TrustedIssuer issuer = trustedIssuers.get(0);
        Assertions.assertEquals(TRUST_ISSUER_NAME, issuer.getName());
        Assertions.assertEquals(CertificateValidationMethod.CHAIN_TRUST, issuer.getCertificateValidationMethod());
        Assertions.assertEquals(TRUST_ISSUER_CERT_CONSTRAINT, issuer.getSubject());

        List<TrustManager> trustManagers = fedContext.getCertificateStores();
        Assertions.assertEquals(1, trustManagers.size());

    }

    @org.junit.jupiter.api.Test
    public void verifyConfigSAML() throws JAXBException {

        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        /**
         * Test JAXB part
         */

        FedizConfigurator configurator = new FedizConfigurator();
        FedizConfig configOut = createConfiguration(false);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        configurator.loadConfig(reader);

        ContextConfig config = configurator.getContextConfig(CONFIG_NAME);
        Assertions.assertNotNull(config);
        AudienceUris audience = config.getAudienceUris();
        Assertions.assertEquals(1, audience.getAudienceItem().size());
        Assertions.assertTrue(config.getProtocol() instanceof SamlProtocolType);

        /**
         * Check Runtime configuration
         */
        FedizContext fedContext = configurator.getFedizContext(CONFIG_NAME);
        Protocol protocol = fedContext.getProtocol();
        Assertions.assertTrue(protocol instanceof SAMLProtocol);
        SAMLProtocol samlProtocol = (SAMLProtocol) protocol;
        Assertions.assertEquals(TARGET_REALM, samlProtocol.getRealm());

        List<String> audienceUris = fedContext.getAudienceUris();
        Assertions.assertEquals(1, audienceUris.size());
        List<TrustedIssuer> trustedIssuers = fedContext.getTrustedIssuers();
        Assertions.assertEquals(1, trustedIssuers.size());
        TrustedIssuer issuer = trustedIssuers.get(0);
        Assertions.assertEquals(TRUST_ISSUER_NAME, issuer.getName());
        Assertions.assertEquals(CertificateValidationMethod.CHAIN_TRUST, issuer.getCertificateValidationMethod());
        Assertions.assertEquals(TRUST_ISSUER_CERT_CONSTRAINT, issuer.getSubject());

        List<TrustManager> trustManagers = fedContext.getCertificateStores();
        Assertions.assertEquals(1, trustManagers.size());

    }

}
