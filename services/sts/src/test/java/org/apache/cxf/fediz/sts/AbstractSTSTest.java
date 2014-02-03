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

package org.apache.cxf.fediz.sts;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.xml.sax.SAXException;

import org.apache.cxf.Bus;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.sts.QNameConstants;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.sts.provider.model.secext.AttributedString;
import org.apache.cxf.ws.security.sts.provider.model.secext.PasswordString;
import org.apache.cxf.ws.security.sts.provider.model.secext.UsernameTokenType;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSConstants;
import org.junit.Assert;
import org.opensaml.saml2.core.Attribute;


public abstract class AbstractSTSTest {

    public static final String SAML2_TOKEN_TYPE =
        "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    public static final String BEARER_KEYTYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";

    protected static final String PROPERTY_URL = "sts-url";
    protected static final String PROPERTY_APPLIESTO = "appliesto";
    protected static final String PROPERTY_CLAIMS = "claims";

    protected static final String PROPERTY_USER = "user";
    protected static final String PROPERTY_PASSWORD = "password";

    protected static final String PROPERTY_TRUSTSTORE = "truststore";
    protected static final String PROPERTY_TRUSTSTORE_PW = "truststore-pw";
    protected static final String PROPERTY_KEYSTORE = "keystore";
    protected static final String PROPERTY_KEYSTORE_PW = "keystore-pw";
    protected static final String PROPERTY_KEYSTORE_KEY_PW = "keystore-key-pw";


    protected Element createUserToken(String username, String password)
        throws JAXBException, SAXException,     IOException, ParserConfigurationException, XMLStreamException {

        JAXBElement<UsernameTokenType> supportingToken = createUsernameToken(username, password);
        final JAXBContext jaxbContext = JAXBContext.newInstance(UsernameTokenType.class);
        StringWriter writer = new StringWriter();
        jaxbContext.createMarshaller().marshal(supportingToken, writer);
        writer.flush();
        InputStream is = new ByteArrayInputStream(writer.toString().getBytes());
        Document doc = StaxUtils.read(is);
        return doc.getDocumentElement();
    }

    protected JAXBElement<UsernameTokenType> createUsernameToken(String name, String password) {
        UsernameTokenType usernameToken = new UsernameTokenType();
        AttributedString username = new AttributedString();
        username.setValue(name);
        usernameToken.setUsername(username);

        // Add a password
        if (password != null) {
            PasswordString passwordString = new PasswordString();
            passwordString.setValue(password);
            passwordString.setType(WSConstants.PASSWORD_TEXT);
            JAXBElement<PasswordString> passwordType = new JAXBElement<PasswordString>(
                QNameConstants.PASSWORD,
                PasswordString.class,
                passwordString);
            usernameToken.getAny().add(passwordType);
        }

        JAXBElement<UsernameTokenType> tokenType = new JAXBElement<UsernameTokenType>(
            QNameConstants.USERNAME_TOKEN,
            UsernameTokenType.class,
            usernameToken);

        return tokenType;
    }
    
    //CHECKSTYLE:OFF
    protected SecurityToken requestSecurityTokenUsernamePassword(String username, String password,
                                                                 String tokenType, String keyType, String realm, 
                                                                 Bus bus, TLSClientParameters tlsClientParameters, 
                                                                 String baseEndpointUrl)
        throws Exception {
        STSClient stsClient = new STSClient(bus);

        String endpointUrl = baseEndpointUrl + realm + "/STSServiceTransportUT";
        stsClient.setWsdlLocation(endpointUrl + "?wsdl");
        stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}SecurityTokenService");
        stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}TransportUT_Port");

        // insert TLS config for STS Client
        HTTPConduit http = (HTTPConduit)stsClient.getClient().getConduit();
        http.setTlsClientParameters(tlsClientParameters);
        TLSClientParameters tlsParameters = http.getTlsClientParameters();
        Assert.assertNotNull("the http conduit's tlsParameters should not be null", tlsParameters);

        Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(SecurityConstants.USERNAME, username);
        properties.put(SecurityConstants.PASSWORD, password);
        properties.put(SecurityConstants.IS_BSP_COMPLIANT, "false");

        stsClient.setProperties(properties);
        stsClient.setTokenType(tokenType);
        stsClient.setKeyType(keyType);

        return stsClient.requestSecurityToken(endpointUrl);
    }

    protected SecurityToken requestSecurityTokenOnbehalfOf(String tokenType, String keyType, String realm,
        String appliesTo, List<String> claims, Element supportingToken,
        Bus bus, TLSClientParameters tlsClientParameters, 
        String baseEndpointUrl)
        throws Exception {
        
        STSClient stsClient = new STSClient(bus);

        String endpointUrl = baseEndpointUrl + realm + "/STSServiceTransport";
        stsClient.setWsdlLocation(endpointUrl + "?wsdl");
        stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}SecurityTokenService");
        stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}Transport_Port");

        // insert TLS config for STS Client
        HTTPConduit http = (HTTPConduit)stsClient.getClient().getConduit();
        http.setTlsClientParameters(tlsClientParameters);
        TLSClientParameters tlsParameters = http.getTlsClientParameters();
        Assert.assertNotNull("the http conduit's tlsParameters should not be null", tlsParameters);

        Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(SecurityConstants.IS_BSP_COMPLIANT, "false");

        Assert.assertNotNull("supportingToken must not be null", supportingToken);
        stsClient.setOnBehalfOf(supportingToken);

        stsClient.setProperties(properties);
        stsClient.setTokenType(tokenType);
        stsClient.setKeyType(keyType);

        if (claims != null) {
            stsClient.setClaims(createClaimsElement(claims));
        }
        if (appliesTo == null) {

            return stsClient.requestSecurityToken();
        } else {
            stsClient.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
            return stsClient.requestSecurityToken(appliesTo);
        }
    }

    protected Element createClaimsElement(List<String> realmClaims) throws Exception {
        if (realmClaims == null || realmClaims.size() == 0) {
            return null;
        }

        W3CDOMStreamWriter writer = new W3CDOMStreamWriter();
        writer.writeStartElement("wst", "Claims", STSUtils.WST_NS_05_12);
        writer.writeNamespace("wst", STSUtils.WST_NS_05_12);
        writer.writeNamespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
        writer.writeAttribute("Dialect", "http://schemas.xmlsoap.org/ws/2005/05/identity");

        if (realmClaims != null && realmClaims.size() > 0) {
            for (String item : realmClaims) {
                writer.writeStartElement("ic", "ClaimType", "http://schemas.xmlsoap.org/ws/2005/05/identity");
                writer.writeAttribute("Uri", item);
                //writer.writeAttribute("Optional", "true");
                writer.writeEndElement();
            }
        }

        writer.writeEndElement();

        return writer.getDocument().getDocumentElement();
    }

    protected Properties readTestProperties(Class clazz, String method) {
        Properties testProps = new Properties();
        String resourceName = "stsclient.properties";
        InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName);
        Assert.assertNotNull("Resource '" + resourceName + "' not found", in);
        try {
            testProps.load(in);
            in.close();

        } catch (IOException e) {
            Assert.fail("Resource '" + resourceName + "' could not be loaded");
        }

        Properties clazzProps = new Properties();
        resourceName = clazz.getSimpleName() + ".properties";
        in = clazz.getResourceAsStream(resourceName);
        Assert.assertNotNull("Resource '" + resourceName + "' not found", in);
        try {
            clazzProps.load(in);
            in.close();

        } catch (IOException e) {
            Assert.fail("Resource '" + resourceName + "' could not be loaded");
        }
        testProps.putAll(clazzProps);

        Properties methodProps = new Properties();
        resourceName = clazz.getSimpleName() + "-" + method + ".properties";
        in = clazz.getResourceAsStream(resourceName);
        Assert.assertNotNull("Resource '" + resourceName + "' not found", in);
        try {
            methodProps.load(in);

        } catch (IOException e) {
            Assert.fail("Resource '" + resourceName + "' could not be loaded");
        }
        testProps.putAll(methodProps);
        return testProps;
    }

    protected void validateIssuedClaims(List<Attribute> attributes, Properties props) {
        for (Attribute attribute: attributes) {
            String expectedValue = (String)props.get(attribute.getName());
            Assert.assertNotNull("Claim '" + attribute.getName() + "' not configured in properties file",
                                 expectedValue);
            String value = attribute.getAttributeValues().get(0).getDOM().getTextContent();
            Assert.assertEquals("Expected claim value '" + expectedValue + "' [" + value + "]", expectedValue, value);
        }
    }

    protected TLSClientParameters initTLSClientParameters(Properties testProps, boolean initKeystore)
        throws URISyntaxException, GeneralSecurityException, IOException {
        TLSClientParameters tlsClientParameters = new TLSClientParameters();
        String truststore = testProps.getProperty(PROPERTY_TRUSTSTORE);
        String tuststorePw = testProps.getProperty(PROPERTY_TRUSTSTORE_PW);
        Assert.assertNotNull("Property '" + PROPERTY_TRUSTSTORE + "' null", truststore);
        Assert.assertNotNull("Property '" + PROPERTY_TRUSTSTORE_PW + "' null", tuststorePw);

        String keystoreFile = testProps.getProperty(PROPERTY_KEYSTORE);
        if (initKeystore && keystoreFile != null) {
            String keystorePassword = testProps.getProperty(PROPERTY_KEYSTORE_PW);
            String keyPassword = testProps.getProperty(PROPERTY_KEYSTORE_KEY_PW);
            Assert.assertNotNull("Property '" + PROPERTY_KEYSTORE + "' null", keystoreFile);
            Assert.assertNotNull("Property '" + PROPERTY_KEYSTORE_PW + "' null", keystorePassword);
            Assert.assertNotNull("Property '" + PROPERTY_KEYSTORE_KEY_PW + "' null", keyPassword);
            Utils.initTLSClientParameters(tlsClientParameters, keystoreFile, keystorePassword,
                                          keyPassword, truststore, tuststorePw);
        } else {
            Utils.initTLSClientParameters(tlsClientParameters, null, null, null, truststore, tuststorePw);
        }
        return tlsClientParameters;
    }

    protected void validateSubject(Properties testProps,
                                   SamlAssertionWrapper assertion) {
        String expectedSamlUser = testProps.getProperty("samluser");
        String samlUser = assertion.getSaml2().getSubject().getNameID().getValue();
        Assert.assertEquals("Expected SAML subject '" + expectedSamlUser + "' [" + samlUser + "]", 
                            expectedSamlUser.toUpperCase(), samlUser.toUpperCase());
    }

    protected void validateIssuer(SamlAssertionWrapper assertion, String realm) {
        String issuer = assertion.getSaml2().getIssuer().getValue();
        Assert.assertTrue("SAML Token issuer should be " + realm + " instead of [" + issuer + "]",
                          issuer.toUpperCase().contains(realm.toUpperCase()));
    }

}