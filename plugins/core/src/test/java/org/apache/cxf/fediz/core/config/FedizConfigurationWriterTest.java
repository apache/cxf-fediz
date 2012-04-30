package org.apache.cxf.fediz.core.config;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.junit.Assert;

public class FedizConfigurationWriterTest {

    private static final String TRUST_ISSUER_CERT_CONSTRAINT = ".*CN=www.sts.com.*";
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
    private static final String KEYSTORE_FILE = "stsstore.jks";

    private static final String FILE_TYPE = "file";

    private static final String KEYSTORE_PASSWORD = "stsspass";
    private static final String AUDIENCE_URI_1 = "http://host_one:port/url";

    private static final String AUTH_TYPE_VALUE = "some auth type";

    private static final String CLAIM_TYPE_1 = "a particular claim type";

    private static final String CONFIG_FILE = "./fediz_test_config.xml";

    private FedizConfig createConfiguration() throws JAXBException {

        FedizConfig rootConfig = new FedizConfig();
        ContextConfig config = new ContextConfig();
        rootConfig.getContextConfig().add(config);

        config.setName(CONFIG_NAME);
        config.setMaximumClockSkew(new BigInteger(CLOCK_SKEW));
        config.setCertificateValidation(ValidationType.CHAIN_TRUST);

        // TrustManagersType tm0 = new TrustManagersType();
        //
        // KeyStoreType ks0 = new KeyStoreType();
        // ks0.setType(FILE_TYPE);
        // ks0.setPassword(KEYSTORE_PASSWORD);
        // ks0.setFile(KEYSTORE_FILE);
        //
        // tm0.setKeyStore(ks0);
        //
        // config.setServiceCertificate(tm0);

        FederationProtocolType protocol = new FederationProtocolType();
        config.setProtocol(protocol);

        TrustedIssuers trustedIssuer = new TrustedIssuers();

        TrustManagersType tm1 = new TrustManagersType();
        tm1.setProvider(TRUST_ISSUER_CERT_CONSTRAINT);
        // CertStoreType cs1 = new CertStoreType();
        // cs1.setFile(CERT_STORE_FILE_1);
        // tm1.setCertStore(cs1);
        // tm1.setFactoryAlgorithm(FACTORY_ALGORITHM_2);

        KeyStoreType ks1 = new KeyStoreType();
        ks1.setType(FILE_TYPE);
        ks1.setPassword(KEYSTORE_PASSWORD);
        ks1.setFile(KEYSTORE_FILE);

        tm1.setKeyStore(ks1);
        trustedIssuer.getTrustedIssuerItem().add(tm1);

        config.setTrustedIssuers(trustedIssuer);

        AuthenticationType authType = new AuthenticationType();
        authType.setType(ArgumentType.STRING);
        authType.setValue(AUTH_TYPE_VALUE);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(AUDIENCE_URI_1);
        config.setAudienceUris(audienceUris);

        protocol.setAuthenticationType(authType);
        protocol.setRoleDelimiter(ROLE_DELIMITER);
        protocol.setRoleURI(ROLE_URI);

        ClaimTypesRequested claimTypeReq = new ClaimTypesRequested();
        ClaimType claimType = new ClaimType();
        claimType.setOptional(true);
        claimType.setType(CLAIM_TYPE_1);
        claimTypeReq.getClaimType().add(claimType);

        protocol.setClaimTypesRequested(claimTypeReq);

        protocol.setFreshness(FRESHNESS_VALUE);

        HomeRealm homeRealm = new HomeRealm();
        homeRealm.setType(ArgumentType.CLASS);
        homeRealm.setValue(HOME_REALM_CLASS);

        protocol.setHomeRealm(homeRealm);
        protocol.setRealm(TARGET_REALM);
        protocol.setReply(REPLY);
        protocol.setRequest("REQUEST");
        protocol.setVersion(PROTOCOL_VERSION);
        protocol.setIssuer(ISSUER);

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
    public void testSaveConfig() throws JAXBException, IOException {
        final JAXBContext jaxbContext = JAXBContext
                .newInstance(FedizConfig.class);

        FederationConfigurator configurator = new FederationConfigurator();
        FedizConfig configOut = createConfiguration();
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(configOut, writer);
        StringReader reader = new StringReader(writer.toString());
        configurator.loadConfig(reader);

        File f = new File(CONFIG_FILE);
        f.createNewFile();

        configurator.saveConfiguration(f);
    }

    @org.junit.Test
    public void testLoadConfig() throws JAXBException {
        FederationConfigurator configurator = new FederationConfigurator();
        File f = new File(CONFIG_FILE);
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
        Assert.assertEquals(1, audience.getAudienceItem().size());
        Assert.assertTrue(config.getProtocol() instanceof FederationProtocolType);
        FederationProtocolType fp = (FederationProtocolType) config
                .getProtocol();

        Assert.assertEquals(HOME_REALM_CLASS, fp.getHomeRealm().getValue());

    }

}