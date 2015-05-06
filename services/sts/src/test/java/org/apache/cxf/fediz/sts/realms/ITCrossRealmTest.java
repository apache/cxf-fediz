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

package org.apache.cxf.fediz.sts.realms;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.fediz.sts.AbstractSTSTest;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.opensaml.saml.saml2.core.Attribute;

/**
 * Some unit tests for the CXF STSClient Issue Binding.
 */
public class ITCrossRealmTest extends AbstractSTSTest {

    static String stsHttpsPort;


    @BeforeClass
    public static void init() {

        stsHttpsPort = System.getProperty("sts.https.port");
        Assert.assertNotNull("Property 'sts.https.port' null", stsHttpsPort);

    }



    /**
     * Test issuing a token from REALM A and re-issue a token from REALM B
     */
    @org.junit.Test
    public void testRealmAtoRealmB() throws Exception {

        SpringBusFactory bf = new SpringBusFactory();

        Properties testProps = readTestProperties(ITCrossRealmTest.class, "testRealmAtoRealmB");

        URL busFile = ITCrossRealmTest.class.getResource("sts-client.xml");
        Bus bus = bf.createBus(busFile.toString());
        SpringBusFactory.setDefaultBus(bus);
        SpringBusFactory.setThreadDefaultBus(bus);

        TLSClientParameters tlsClientParameters = initTLSClientParameters(testProps, false);

        String stsUrl = testProps.getProperty(PROPERTY_URL);
        if (stsUrl == null || stsUrl.length() == 0) {
            stsUrl = "https://localhost:" + String.valueOf(stsHttpsPort) + "/fediz-idp-sts/";
        }

        String user = testProps.getProperty(PROPERTY_USER);
        String password = testProps.getProperty(PROPERTY_PASSWORD);
        String appliesTo = testProps.getProperty(PROPERTY_APPLIESTO);
        Assert.assertNotNull("Property '" + PROPERTY_APPLIESTO + "' null", appliesTo);

        // Get a token
        SecurityToken idpToken = requestSecurityTokenUsernamePassword(
                                                                      user,
                                                                      password,
                                                                      SAML2_TOKEN_TYPE,
                                                                      BEARER_KEYTYPE,
                                                                      "REALMA",
                                                                      bus,
                                                                      tlsClientParameters,
                                                                      stsUrl);

        Assert.assertTrue(SAML2_TOKEN_TYPE.equals(idpToken.getTokenType()));
        Assert.assertTrue(idpToken.getToken() != null);
        
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(idpToken.getToken());
        validateIssuer(assertion, "STS Realm A");

        
        List<String> claimsList = null;
        String claims = testProps.getProperty(PROPERTY_CLAIMS);
        if (claims != null && claims.length() > 0) {
            claimsList = new ArrayList<>();
            StringTokenizer st = new StringTokenizer(claims, ";");
            while (st.hasMoreTokens()) {
                claimsList.add(st.nextToken());
            }
        }
        
        // Need client auth for the second call
        tlsClientParameters = initTLSClientParameters(testProps, true);
        
        SecurityToken rpToken = requestSecurityTokenOnbehalfOf(
                                                               SAML2_TOKEN_TYPE,
                                                               BEARER_KEYTYPE,
                                                               "REALMB",
                                                               appliesTo,
                                                               claimsList,
                                                               idpToken.getToken(),
                                                               bus,
                                                               tlsClientParameters,
                                                               stsUrl);

        Assert.assertTrue(SAML2_TOKEN_TYPE.equals(rpToken.getTokenType()));
        Assert.assertTrue(rpToken.getToken() != null);
        
        assertion = new SamlAssertionWrapper(rpToken.getToken());
        this.validateSubject(testProps, assertion);
        validateIssuer(assertion, "STS Realm B");

        //AssertionWrapper assertion = new AssertionWrapper(rpToken.getToken());
        //validateSubject(testProps, assertion);
        //String realm = "GAD";
        //validateIssuer(assertion, realm);
        //List<Attribute> attributes = assertion.getSaml2().getAttributeStatements().get(0).getAttributes();
        //validateIssuedClaims(attributes, testProps);

        bus.shutdown(true);
    }
    
    /**
     * Test issuing a token from REALM A and re-issue a token from REALM B
     */
    @org.junit.Test
    public void testRealmAtoRealmBWithClaims() throws Exception {

        SpringBusFactory bf = new SpringBusFactory();

        Properties testProps = readTestProperties(ITCrossRealmTest.class, "testRealmAtoRealmBWithClaims");

        URL busFile = ITCrossRealmTest.class.getResource("sts-client.xml");
        Bus bus = bf.createBus(busFile.toString());
        SpringBusFactory.setDefaultBus(bus);
        SpringBusFactory.setThreadDefaultBus(bus);

        TLSClientParameters tlsClientParameters = initTLSClientParameters(testProps, false);

        String stsUrl = testProps.getProperty(PROPERTY_URL);
        if (stsUrl == null || stsUrl.length() == 0) {
            stsUrl = "https://localhost:" + String.valueOf(stsHttpsPort) + "/fediz-idp-sts/";
        }

        String user = testProps.getProperty(PROPERTY_USER);
        String password = testProps.getProperty(PROPERTY_PASSWORD);
        String appliesTo = testProps.getProperty(PROPERTY_APPLIESTO);
        Assert.assertNotNull("Property '" + PROPERTY_APPLIESTO + "' null", appliesTo);

        // Get a token
        SecurityToken idpToken = requestSecurityTokenUsernamePassword(
                                                                      user,
                                                                      password,
                                                                      SAML2_TOKEN_TYPE,
                                                                      BEARER_KEYTYPE,
                                                                      "REALMA",
                                                                      bus,
                                                                      tlsClientParameters,
                                                                      stsUrl);

        Assert.assertTrue(SAML2_TOKEN_TYPE.equals(idpToken.getTokenType()));
        Assert.assertTrue(idpToken.getToken() != null);
        
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(idpToken.getToken());
        validateIssuer(assertion, "STS Realm A");

        
        List<String> claimsList = null;
        String claims = testProps.getProperty(PROPERTY_CLAIMS);
        if (claims != null && claims.length() > 0) {
            claimsList = new ArrayList<>();
            StringTokenizer st = new StringTokenizer(claims, ";");
            while (st.hasMoreTokens()) {
                claimsList.add(st.nextToken());
            }
        }
        
        // Need client auth for the second call
        tlsClientParameters = initTLSClientParameters(testProps, true);
        
        SecurityToken rpToken = requestSecurityTokenOnbehalfOf(
                                                               SAML2_TOKEN_TYPE,
                                                               BEARER_KEYTYPE,
                                                               "REALMB",
                                                               appliesTo,
                                                               claimsList,
                                                               idpToken.getToken(),
                                                               bus,
                                                               tlsClientParameters,
                                                               stsUrl);

        Assert.assertTrue(SAML2_TOKEN_TYPE.equals(rpToken.getTokenType()));
        Assert.assertTrue(rpToken.getToken() != null);
        
        assertion = new SamlAssertionWrapper(rpToken.getToken());
        this.validateSubject(testProps, assertion);
        validateIssuer(assertion, "STS Realm B");
        
        List<Attribute> attributes = assertion.getSaml2().getAttributeStatements().get(0).getAttributes();
        validateIssuedClaims(attributes, testProps);

        //AssertionWrapper assertion = new AssertionWrapper(rpToken.getToken());
        //validateSubject(testProps, assertion);
        //String realm = "GAD";
        //validateIssuer(assertion, realm);
        //List<Attribute> attributes = assertion.getSaml2().getAttributeStatements().get(0).getAttributes();
        //validateIssuedClaims(attributes, testProps);

        bus.shutdown(true);
    }
    
}
