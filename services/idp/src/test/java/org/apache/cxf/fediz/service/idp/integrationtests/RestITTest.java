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
package org.apache.cxf.fediz.service.idp.integrationtests;

import java.net.URL;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.rest.Idps;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class RestITTest {
        
    private static String idpHttpsPort;
    private static Bus bus;


    @BeforeClass
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.webflow", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security.web", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf.fediz", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf", "info");

        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);

        SpringBusFactory bf = new SpringBusFactory();
        
        URL busFile = RestITTest.class.getResource("/rest-client.xml");
        bus = bf.createBus(busFile.toString());
        SpringBusFactory.setDefaultBus(bus);
        SpringBusFactory.setThreadDefaultBus(bus);
        
    }
    
    @AfterClass
    public static void cleanup() {
        if (bus != null) {
            bus.shutdown(true);
        }
    }
    
    @Test
    public void testGetAllIdps() {
        String address = "https://localhost:" + idpHttpsPort + "/fediz-idp/services/rs";
        Client client = ClientBuilder.newClient();
        Idps idps = client.target(address).path("idps")
            .request("application/xml").get(Idps.class);
        Assert.assertEquals(1L, idps.getIdps().size());
        
        Idp idp = idps.getIdps().iterator().next();
        Assert.assertEquals("Certificate doesn't match",
                            "stsKeystoreA.properties", idp.getCertificate());
        Assert.assertEquals("Certificate password doesn't match",
                            "realma", idp.getCertificatePassword());
        Assert.assertEquals("Realm doesn't match",
                            "urn:org:apache:cxf:fediz:idp:realm-A", idp.getRealm());
        Assert.assertEquals("ServiceDescription doesn't match",
                            "IDP of Realm A", idp.getServiceDescription());
        Assert.assertEquals("ServiceDisplayName doesn't match",
                            "REALM A", idp.getServiceDisplayName());
        Assert.assertEquals("IdpUrl doesn't match",
                            "https://localhost:9443/fediz-idp/federation", idp.getIdpUrl());
        Assert.assertEquals("StsUrl doesn't match",
                            "https://localhost:9443/fediz-idp-sts/REALMA", idp.getStsUrl());
        Assert.assertEquals("Uri doesn't match",
                            "realma", idp.getUri());
        Assert.assertTrue("ProvideIDPList doesn't match", idp.isProvideIDPList());
        Assert.assertTrue("UseCurrentIDP doesn't match", idp.isUseCurrentIDP());
        Assert.assertEquals("Number of AuthenticationURIs doesn't match",
                            1, idp.getAuthenticationURIs().size());
        Assert.assertEquals("Number of SupportedProtocols doesn't match",
                            2, idp.getSupportedProtocols().size());
        Assert.assertEquals("Number of TokenTypesOffered doesn't match",
                            2, idp.getTokenTypesOffered().size());
        Assert.assertEquals("Number of applications doesn't match",
                            1, idp.getApplications().size());
        Assert.assertEquals("Number of trusted IDPs doesn't match",
                            1, idp.getTrustedIdps().size());
        Assert.assertEquals("Number of claims doesn't match",
                            4, idp.getClaimTypesOffered().size());
        
    }
    
    @Test
    public void testReadExistingIdpEmbeddedTrustedIdps() {
        String address = "https://localhost:" + idpHttpsPort + "/fediz-idp/services/rs";
        Client client = ClientBuilder.newClient();
        Idp idp = client.target(address).path("idps/").path("urn:org:apache:cxf:fediz:idp:realm-A")
            .request("application/xml").get(Idp.class);
        Assert.assertEquals("", "urn:org:apache:cxf:fediz:idp:realm-A", idp.getRealm());
    }

    
    
}
