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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Base64;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.RequestClaim;
import org.apache.cxf.fediz.service.idp.rest.Claims;
import org.apache.cxf.fediz.service.idp.rest.Entitlements;
import org.apache.cxf.fediz.service.idp.rest.Idps;
import org.apache.cxf.fediz.service.idp.rest.Roles;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RestITTest {

    private static String idpHttpsPort;
    private static String realm;
    private static Bus bus;


    @BeforeAll
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
        Assertions.assertNotNull(idpHttpsPort, "Property 'idp.https.port' null");

        realm = System.getProperty("realm");
        Assertions.assertNotNull(realm, "Property 'realm' null");

        SpringBusFactory bf = new SpringBusFactory();

        URL busFile = RestITTest.class.getResource("/rest-client.xml");
        bus = bf.createBus(busFile.toString());
        SpringBusFactory.setDefaultBus(bus);
        SpringBusFactory.setThreadDefaultBus(bus);

    }

    @AfterAll
    public static void cleanup() {
        if (bus != null) {
            bus.shutdown(true);
        }
    }

    @Test
    public void testGetAllIdps() throws MalformedURLException {
        String address = "https://localhost:" + idpHttpsPort + "/" + getContextName() + "/services/rs";
        Client client = ClientBuilder.newClient();
        Idps idps = client.target(address).path("idps")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .get(Idps.class);
        Assertions.assertEquals(1L, idps.getIdps().size());

        Idp idp = idps.getIdps().iterator().next();
        if ("realm-a".equals(realm)) {
            Assertions.assertEquals("stsKeystoreA.properties", idp.getCertificate(), "Certificate doesn't match");
            Assertions.assertEquals("realma", idp.getCertificatePassword(), "Certificate password doesn't match");
            Assertions.assertEquals("urn:org:apache:cxf:fediz:idp:realm-A", idp.getRealm(), "Realm doesn't match");
            Assertions.assertEquals("IDP of Realm A", idp.getServiceDescription(), "ServiceDescription doesn't match");
            Assertions.assertEquals("REALM A", idp.getServiceDisplayName(), "ServiceDisplayName doesn't match");
            Assertions.assertEquals(new URL("https://localhost:9443/fediz-idp/federation"), idp.getIdpUrl(),
                    "IdpUrl doesn't match");
            Assertions.assertEquals(new URL("https://localhost:9443/fediz-idp-sts/REALMA"), idp.getStsUrl(),
                    "StsUrl doesn't match");
            Assertions.assertEquals("realma", idp.getUri(), "Uri doesn't match");
            Assertions.assertTrue(idp.isProvideIdpList(), "ProvideIDPList doesn't match");
            Assertions.assertTrue(idp.isUseCurrentIdp(), "UseCurrentIDP doesn't match");
            Assertions.assertEquals(4, idp.getAuthenticationURIs().size(),
                    "Number of AuthenticationURIs doesn't match");
            Assertions.assertEquals(2, idp.getSupportedProtocols().size(),
                    "Number of SupportedProtocols doesn't match");
            Assertions.assertEquals(2, idp.getTokenTypesOffered().size(),
                    "Number of TokenTypesOffered doesn't match");
            Assertions.assertEquals(2, idp.getApplications().size(),
                    "Number of applications doesn't match");
            Assertions.assertEquals(1, idp.getTrustedIdps().size(),
                    "Number of trusted IDPs doesn't match");
            Assertions.assertEquals(4, idp.getClaimTypesOffered().size(),
                    "Number of claims doesn't match");
        } else {
            Assertions.assertEquals("stsKeystoreB.properties", idp.getCertificate(), "Certificate doesn't match");
            Assertions.assertEquals("realmb", idp.getCertificatePassword(), "Certificate password doesn't match");
            Assertions.assertEquals("urn:org:apache:cxf:fediz:idp:realm-B", idp.getRealm(), "Realm doesn't match");
            Assertions.assertEquals("IDP of Realm B", idp.getServiceDescription(), "ServiceDescription doesn't match");
            Assertions.assertEquals("REALM B", idp.getServiceDisplayName(), "ServiceDisplayName doesn't match");
            Assertions.assertEquals(new URL("https://localhost:12443/fediz-idp-remote/federation"), idp.getIdpUrl(),
                    "IdpUrl doesn't match");
            Assertions.assertEquals(new URL("https://localhost:12443/fediz-idp-sts/REALMB"), idp.getStsUrl(),
                    "StsUrl doesn't match");
            Assertions.assertEquals("realmb", idp.getUri(), "Uri doesn't match");
            Assertions.assertTrue(idp.isProvideIdpList(), "ProvideIDPList doesn't match");
            Assertions.assertTrue(idp.isUseCurrentIdp(), "UseCurrentIDP doesn't match");
            Assertions.assertEquals(4, idp.getAuthenticationURIs().size(),
                    "Number of AuthenticationURIs doesn't match");
            Assertions.assertEquals(2, idp.getSupportedProtocols().size(),
                    "Number of SupportedProtocols doesn't match");
            Assertions.assertEquals(2, idp.getTokenTypesOffered().size(), "Number of TokenTypesOffered doesn't match");
            Assertions.assertEquals(1, idp.getApplications().size(), "Number of applications doesn't match");
            Assertions.assertEquals(4, idp.getClaimTypesOffered().size(), "Number of claims doesn't match");
        }
    }

    @Test
    public void testReadExistingIdpEmbeddedTrustedIdps() {
        String address = "https://localhost:" + idpHttpsPort + "/" + getContextName() + "/services/rs";
        Client client = ClientBuilder.newClient();

        if ("realm-a".equals(realm)) {
            Idp idp = client.target(address).path("idps/").path("urn:org:apache:cxf:fediz:idp:realm-A")
                .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
                .get(Idp.class);
            Assertions.assertEquals("urn:org:apache:cxf:fediz:idp:realm-A", idp.getRealm());
        } else {
            Idp idp = client.target(address).path("idps/").path("urn:org:apache:cxf:fediz:idp:realm-B")
                .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
                .get(Idp.class);
            Assertions.assertEquals("urn:org:apache:cxf:fediz:idp:realm-B", idp.getRealm());
        }
    }

    @Test
    public void testAddClaimToApplication() {

        String address = "https://localhost:" + idpHttpsPort + "/" + getContextName() + "/services/rs";
        Client client = ClientBuilder.newClient();

        String realmToAdd = "urn:org:apache:cxf:fediz:fedizhelloworld:testaddclaim";
        Application application = new Application();
        application.setRealm(realmToAdd);
        application.setEncryptionCertificate("");
        application.setLifeTime(3600);
        application.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("ApplicationServiceType");
        application.setServiceDescription("Fedizhelloworld description");
        application.setServiceDisplayName("Fedizhelloworld");
        application.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");

        Response response = client.target(address).path("applications/")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .post(Entity.entity(application, MediaType.APPLICATION_XML));
        Assertions.assertEquals(Status.CREATED.getStatusCode(), response.getStatus());

        //Testcase
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));

        response = client.target(address).path("applications").path(realmToAdd).path("claims")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .post(Entity.entity(requestClaim, MediaType.APPLICATION_XML));
        Assertions.assertEquals(Status.NO_CONTENT.getStatusCode(), response.getStatus());

        application = client.target(address).path("applications").path(realmToAdd).queryParam("expand", "claims")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .get(Application.class);
        Assertions.assertEquals(1, application.getRequestedClaims().size(),
                "Claims size should be 1 instead of " + application.getRequestedClaims().size());
    }

    @Test
    public void testGetAllClaims() {
        String address = "https://localhost:" + idpHttpsPort + "/" + getContextName() + "/services/rs";
        Client client = ClientBuilder.newClient();
        Claims claims = client.target(address).path("claims")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .get(Claims.class);
        Assertions.assertEquals(2, claims.getClaims().size());
    }

    @Test
    public void testGetAllEntitlements() {
        String address = "https://localhost:" + idpHttpsPort + "/" + getContextName() + "/services/rs";
        Client client = ClientBuilder.newClient();
        Entitlements entitlements = client.target(address).path("entitlements")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .get(Entitlements.class);
        Assertions.assertEquals(5, entitlements.getEntitlements().size());
    }

    @Test
    public void testGetAllRoles() {
        String address = "https://localhost:" + idpHttpsPort + "/" + getContextName() + "/services/rs";
        Client client = ClientBuilder.newClient();
        Roles roles = client.target(address).path("roles")
            .request("application/xml").header("Authorization", getBasicAuthentication("admin", "password"))
            .get(Roles.class);
        Assertions.assertEquals(2, roles.getRoles().size());
    }

    private static String getBasicAuthentication(String username, String password) {
        String token = username + ':' + password;
        return "Basic " + Base64.getEncoder().encodeToString(token.getBytes());
    }

    private String getContextName() {
        if ("realm-a".equals(realm)) {
            return "fediz-idp";
        }
        return "fediz-idp-remote";
    }

}
