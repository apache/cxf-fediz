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
package org.apache.cxf.fediz.service.idp.service.jpa;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.service.IdpDAO;
import org.apache.wss4j.dom.WSConstants;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.orm.jpa.JpaObjectRetrievalFailureException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.Assert;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:testContext.xml" })
public class IdpDAOJPATest {

    @Autowired
    private IdpDAO idpDAO;
    
    
    @BeforeClass
    public static void init() {
        System.setProperty("spring.profiles.active", "jpa");
    }
    
    
    @Test
    public void testReadAllIdps() {
        List<Idp> idps = idpDAO.getIdps(0, 999, null);
        // Idp could have been removed, Order not given as per JUnit design
        Assert.isTrue(0 < idps.size(), "Size doesn't match [" + idps.size() + "]");
    }
    
    
    @Test
    public void testReadExistingIdpEmbeddedAll() throws MalformedURLException {
        Idp idp = idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:realm-A",
                                                                Arrays.asList("all"));
        
        Assert.isTrue("stsKeystoreA.properties".equals(idp.getCertificate()),
                      "Certificate doesn't match");
        Assert.isTrue("realma".equals(idp.getCertificatePassword()),
                      "Certificate password doesn't match");
        Assert.isTrue("urn:org:apache:cxf:fediz:idp:realm-A".equals(idp.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue("IDP of Realm A".equals(idp.getServiceDescription()),
                      "ServiceDescription doesn't match");
        Assert.isTrue("REALM A".equals(idp.getServiceDisplayName()),
                      "ServiceDisplayName doesn't match");        
        Assert.isTrue(new URL("https://localhost:9443/fediz-idp/federation").equals(idp.getIdpUrl()),
                      "IdpUrl doesn't match");
        Assert.isTrue(new URL("https://localhost:9443/fediz-idp-sts/REALMA").equals(idp.getStsUrl()),
                      "StsUrl doesn't match");
        Assert.isTrue("realma".equals(idp.getUri()),
                      "Uri doesn't match");
        Assert.isTrue(idp.isProvideIdpList(),
                      "ProvideIDPList doesn't match");
        Assert.isTrue(idp.isUseCurrentIdp(),
                      "UseCurrentIDP doesn't match");
        Assert.isTrue(1 == idp.getAuthenticationURIs().size(),
                      "Number of AuthenticationURIs doesn't match");
        Assert.isTrue(2 == idp.getSupportedProtocols().size(),
                      "Number of SupportedProtocols doesn't match");
        Assert.isTrue(2 == idp.getTokenTypesOffered().size(),
                      "Number of TokenTypesOffered doesn't match");
        Assert.isTrue(1 == idp.getApplications().size(),
                      "Number of applications doesn't match");
        Assert.isTrue(1 == idp.getTrustedIdps().size(),
                      "Number of trusted IDPs doesn't match");
        Assert.isTrue(4 == idp.getClaimTypesOffered().size(),
                      "Number of claims doesn't match");
    }
    
    @Test
    public void testReadExistingIdpEmbeddedTrustedIdps() {
        Idp idp = idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:realm-A",
                                                                Arrays.asList("trusted-idps"));
        
        Assert.isTrue(1 == idp.getTrustedIdps().size(),
                      "Number of trusted IDPs doesn't match");
    }
    
    @Test
    public void testReadExistingIdpEmbeddedClaims() {
        Idp idp = idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:realm-A",
                                                                Arrays.asList("claims"));
        
        Assert.isTrue(4 == idp.getClaimTypesOffered().size(),
                      "Number of claims doesn't match");
    }
    
    @Test
    public void testReadExistingIdpEmbeddedApplications() {
        Idp idp = idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:realm-A",
                                                                Arrays.asList("applications"));
        
        Assert.isTrue(1 == idp.getApplications().size(),
                      "Number of applications doesn't match");
    }
    
    @Test
    public void testReadExistingIdpEmbeddedNull() {
        Idp idp = idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:realm-A",
                                                                null);
        
        Assert.isTrue(0 == idp.getClaimTypesOffered().size(),
                      "Number of claims doesn't match");
        Assert.isTrue(0 == idp.getApplications().size(),
                      "Number of applications doesn't match");
        Assert.isTrue(0 == idp.getTrustedIdps().size(),
                      "Number of trusted IDPs doesn't match");
       
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryReadNonexistingIdp() {
        idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:NOTEXIST", null);
    }
    
    
    @Test
    public void testAddNewIdp() throws MalformedURLException {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:testadd");
        idp.setCertificate("stsKeystoreA.properties");
        idp.setCertificatePassword("realma");
        idp.setIdpUrl(new URL("https://localhost:9443/fediz-idp/federation"));
        idp.setStsUrl(new URL("https://localhost:9443/fediz-idp-sts/REALMN"));
        idp.setServiceDisplayName("NEW REALM");
        idp.setServiceDescription("IDP of New Realm");
        idp.setUri("realmn");
        idp.setProvideIdpList(true);
        Map<String, String> authUris = new HashMap<String, String>();
        authUris.put("default", "/login/default");
        idp.setAuthenticationURIs(authUris);
        List<String> protocols = new ArrayList<String>();
        protocols.add("http://docs.oasis-open.org/wsfed/federation/200706");
        protocols.add("http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        idp.setSupportedProtocols(protocols);
        List<String> tokenTypes = new ArrayList<String>();
        tokenTypes.add(WSConstants.SAML2_NS);
        tokenTypes.add(WSConstants.SAML_NS);
        idp.setTokenTypesOffered(tokenTypes);
        idp.setUseCurrentIdp(true);
        
        idpDAO.addIdp(idp);
        
        idp = idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:testadd", null);
        
        Assert.isTrue("stsKeystoreA.properties".equals(idp.getCertificate()),
                      "Certificate doesn't match");
        Assert.isTrue("realma".equals(idp.getCertificatePassword()),
                      "Certificate password doesn't match");
        Assert.isTrue("urn:org:apache:cxf:fediz:idp:testadd".equals(idp.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue("IDP of New Realm".equals(idp.getServiceDescription()),
                      "ServiceDescription doesn't match");
        Assert.isTrue("NEW REALM".equals(idp.getServiceDisplayName()),
                      "ServiceDisplayName doesn't match");        
        Assert.isTrue(new URL("https://localhost:9443/fediz-idp/federation").equals(idp.getIdpUrl()),
                      "IdpUrl doesn't match");
        Assert.isTrue(new URL("https://localhost:9443/fediz-idp-sts/REALMN").equals(idp.getStsUrl()),
                      "StsUrl doesn't match");
        Assert.isTrue("realmn".equals(idp.getUri()),
                      "Uri doesn't match");
        Assert.isTrue(idp.isProvideIdpList(),
                      "ProvideIDPList doesn't match");
        Assert.isTrue(idp.isUseCurrentIdp(),
                      "UseCurrentIDP doesn't match");
        Assert.isTrue(1 == idp.getAuthenticationURIs().size(),
                      "Number of AuthenticationURIs doesn't match");
        Assert.isTrue(2 == idp.getSupportedProtocols().size(),
                      "Number of SupportedProtocols doesn't match");
        Assert.isTrue(2 == idp.getTokenTypesOffered().size(),
                      "Number of TokenTypesOffered doesn't match");
        Assert.isTrue(0 == idp.getApplications().size(),
                      "Number of applications doesn't match");
        Assert.isTrue(0 == idp.getTrustedIdps().size(),
                      "Number of trusted IDPs doesn't match");
        Assert.isTrue(0 == idp.getClaimTypesOffered().size(),
                      "Number of claims doesn't match");

    }
    
    
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingIdp() throws MalformedURLException {
        Idp idp = createIdp("urn:org:apache:cxf:fediz:idp:realm-A");
        idpDAO.addIdp(idp);
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryRemoveUnknownIdp() {
        idpDAO.deleteIdp("urn:org:apache:cxf:fediz:idp:NOTEXIST");
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testRemoveExistingIdp() throws MalformedURLException {
        Idp idp = createIdp("urn:org:apache:cxf:fediz:idp:testdelete");
        
        idpDAO.addIdp(idp);
        
        idpDAO.deleteIdp("urn:org:apache:cxf:fediz:idp:testdelete");
        
        idpDAO.getIdp("urn:org:apache:cxf:fediz:idp:testdelete", null);
    }
    
    @Test
    public void testUpdateIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:idp:testupdate";
        //Prepare
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        //Testcase
        idp = new Idp();
        idp.setRealm(realm);
        idp.setCertificate("UstsKeystoreA.properties");
        idp.setCertificatePassword("Urealma");
        idp.setIdpUrl(new URL("https://localhost:9443/fediz-idp/federationUU"));
        idp.setStsUrl(new URL("https://localhost:9443/fediz-idp-sts/REALMAUU"));
        idp.setServiceDisplayName("UNEW REALM");
        idp.setServiceDescription("UIDP of New Realm");
        idp.setUri("Urealmn");
        idp.setProvideIdpList(true);
        Map<String, String> authUris = new HashMap<String, String>();
        authUris.put("default", "/login/default");
        idp.setAuthenticationURIs(authUris);
        List<String> protocols = new ArrayList<String>();
        protocols.add("http://docs.oasis-open.org/wsfed/federation/200706");
        idp.setSupportedProtocols(protocols);
        List<String> tokenTypes = new ArrayList<String>();
        tokenTypes.add(WSConstants.SAML2_NS);
        idp.setTokenTypesOffered(tokenTypes);
        idp.setUseCurrentIdp(false);
        idpDAO.updateIdp(realm, idp);
        
        idp = idpDAO.getIdp(realm, null);
        
        Assert.isTrue("UstsKeystoreA.properties".equals(idp.getCertificate()),
                      "Certificate doesn't match");
        Assert.isTrue("Urealma".equals(idp.getCertificatePassword()),
                      "Certificate password doesn't match");
        Assert.isTrue(realm.equals(idp.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue("UIDP of New Realm".equals(idp.getServiceDescription()),
                      "ServiceDescription doesn't match");
        Assert.isTrue("UNEW REALM".equals(idp.getServiceDisplayName()),
                      "ServiceDisplayName doesn't match");        
        Assert.isTrue(new URL("https://localhost:9443/fediz-idp/federationUU").equals(idp.getIdpUrl()),
                      "IdpUrl doesn't match");
        Assert.isTrue(new URL("https://localhost:9443/fediz-idp-sts/REALMAUU").equals(idp.getStsUrl()),
                      "StsUrl doesn't match");
        Assert.isTrue("Urealmn".equals(idp.getUri()),
                      "Uri doesn't match");
        Assert.isTrue(idp.isProvideIdpList(),
                      "ProvideIDPList doesn't match");
        Assert.isTrue(!idp.isUseCurrentIdp(),
                      "UseCurrentIDP doesn't match");
        Assert.isTrue(1 == idp.getAuthenticationURIs().size(),
                      "Number of AuthenticationURIs doesn't match");
        Assert.isTrue(1 == idp.getSupportedProtocols().size(),
                      "Number of SupportedProtocols doesn't match");
        Assert.isTrue(1 == idp.getTokenTypesOffered().size(),
                      "Number of TokenTypesOffered doesn't match");
        Assert.isTrue(0 == idp.getApplications().size(),
                      "Number of applications doesn't match");
        Assert.isTrue(0 == idp.getTrustedIdps().size(),
                      "Number of trusted IDPs doesn't match");
        Assert.isTrue(0 == idp.getClaimTypesOffered().size(),
                      "Number of claims doesn't match");
        
    }
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testUpdateUnknownIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:idp:testupdate2";
        
        //Prepare
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        //Testcase
        idp = new Idp();
        idp.setRealm(realm);
        idp.setCertificate("UstsKeystoreA.properties");
        idp.setCertificatePassword("Urealma");
        idp.setIdpUrl(new URL("https://localhost:9443/fediz-idp/federationUU"));
        idp.setStsUrl(new URL("https://localhost:9443/fediz-idp-sts/REALMNUU"));
        idp.setServiceDisplayName("UNEW REALM");
        idp.setServiceDescription("UIDP of New Realm");
        idp.setUri("Urealmn");
        idp.setProvideIdpList(true);
        Map<String, String> authUris = new HashMap<String, String>();
        authUris.put("default", "/login/default");
        idp.setAuthenticationURIs(authUris);
        List<String> protocols = new ArrayList<String>();
        protocols.add("http://docs.oasis-open.org/wsfed/federation/200706");
        idp.setSupportedProtocols(protocols);
        List<String> tokenTypes = new ArrayList<String>();
        tokenTypes.add(WSConstants.SAML2_NS);
        idp.setTokenTypesOffered(tokenTypes);
        idp.setUseCurrentIdp(false);
        idpDAO.updateIdp("urn:UNKNOWN", idp);
    }
    
    @Test
    public void testAddClaimToIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:idp:testaddclaim";
        
        //Prepare
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        //Testcase
        Claim claim = new Claim();
        claim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        
        idpDAO.addClaimToIdp(idp, claim);
               
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        
        Assert.isTrue(1 == idp.getClaimTypesOffered().size(), "claimTypesOffered size doesn't match");
    }
    
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingClaimToIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
        
        Claim claim = new Claim();
        claim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        
        idpDAO.addClaimToIdp(idp, claim);
    }
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryAddUnknownClaimToIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
        
        Claim claim = new Claim();
        claim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/UNKOWN"));
        
        idpDAO.addClaimToIdp(idp, claim);
        
    }
    
    @Test
    public void testRemoveClaimFromIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:fedizhelloworld:testremoveclaim";
        //Prepare step
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        Claim claim = new Claim();
        claim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        idpDAO.addClaimToIdp(idp, claim);
               
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        Assert.isTrue(1 == idp.getClaimTypesOffered().size(),
                      "claimTypesOffered size doesn't match [" + idp.getClaimTypesOffered().size() + "]");
        
        //Testcase
        idpDAO.removeClaimFromIdp(idp, claim);
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        Assert.isTrue(0 == idp.getClaimTypesOffered().size(),
                      "claimTypesOffered size doesn't match [" + idp.getClaimTypesOffered().size() + "]");
    }
    
    @Test(expected = JpaObjectRetrievalFailureException.class)
    public void testTryRemoveNotAssignedClaimFromIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
                
        Claim claim = new Claim();
        claim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/city"));
        
        idpDAO.removeClaimFromIdp(idp, claim);
    }
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryRemoveUnknownClaimFromIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
                
        Claim claim = new Claim();
        claim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/UNKNOWN"));
        
        idpDAO.removeClaimFromIdp(idp, claim);
    }
    
    @Test
    public void testAddApplicationToIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:app:testaddApplication";
        
        //Prepare
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        //Testcase
        //Application app = createApplication(realm);
        Application app = new Application();
        app.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
        idpDAO.addApplicationToIdp(idp, app);
               
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        
        Assert.isTrue(1 == idp.getApplications().size(), "applications size doesn't match");
    }
    
    
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingApplicationToIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
        
        Application app = new Application();
        app.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
        
        idpDAO.addApplicationToIdp(idp, app);
    }
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryAddUnknownApplicationToIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
        
        Application app = new Application();
        app.setRealm("urn:org:apache:cxf:fediz:UNKNOWN");
        
        idpDAO.addApplicationToIdp(idp, app);
        
    }
    
    @Test
    public void testRemoveApplicationFromIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:fedizhelloworld:testremoveapp";
        //Prepare step
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        Application app = new Application();
        app.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
        idpDAO.addApplicationToIdp(idp, app);
               
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        Assert.isTrue(1 == idp.getApplications().size(),
                      "applications size doesn't match [" + idp.getApplications().size() + "]");
        
        //Testcase
        idpDAO.removeApplicationFromIdp(idp, app);
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        Assert.isTrue(0 == idp.getApplications().size(),
                      "applications size doesn't match [" + idp.getApplications().size() + "]");
    }
    
    
    @Test(expected = JpaObjectRetrievalFailureException.class)
    public void testTryRemoveNotAssignedApplicationFromIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
                
        Application app = new Application();
        app.setRealm("myrealm2");
        
        idpDAO.removeApplicationFromIdp(idp, app);
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryRemoveUnknownApplicationFromIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
                
        Application app = new Application();
        app.setRealm("urn:org:apache:cxf:fediz:UNKNOWN");
        
        idpDAO.removeApplicationFromIdp(idp, app);
    }
    
    
    
    
    
    
    @Test
    public void testAddTrustedIdpToIdp() throws MalformedURLException {
        String realm = "urn:org:apache:cxf:fediz:trusted-idp:testaddTrustedIdp";
        
        //Prepare
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        //Testcase
        //Application app = createApplication(realm);
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm("urn:org:apache:cxf:fediz:idp:realm-B");
        idpDAO.addTrustedIdpToIdp(idp, trustedIdp);
               
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        
        Assert.isTrue(1 == idp.getTrustedIdps().size(), "applications size doesn't match");
    }
    
    /*
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingTrustedIdpToIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
        
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm("urn:org:apache:cxf:fediz:idp:realm-B");
        
        idpDAO.addTrustedIdpToIdp(idp, trustedIdp);
    }
    
    @Test(expected = NoResultException.class)
    public void testTryAddUnknownTrustedIdpToIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
        
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm("urn:org:apache:cxf:fediz:UNKNOWN");
        
        idpDAO.addTrustedIdpToIdp(idp, trustedIdp);
    }
    
    @Test
    public void testRemoveTrustedIdpFromIdp() {
        String realm = "urn:org:apache:cxf:fediz:trustedidp:testremove";
        //Prepare step
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm("urn:org:apache:cxf:fediz:idp:realm-B");
        idpDAO.addTrustedIdpToIdp(idp, trustedIdp);
               
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        Assert.isTrue(1 == idp.getTrustedIdps().size(),
                      "trustedIdps size doesn't match [" + idp.getTrustedIdps().size() + "]");
        
        //Testcase
        idpDAO.removeTrustedIdpFromIdp(idp, trustedIdp);
        idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        Assert.isTrue(0 == idp.getTrustedIdps().size(),
                      "trustedIdps size doesn't match [" + idp.getTrustedIdps().size() + "]");
    }
    
    
    @Test(expected = EntityNotFoundException.class)
    public void testTryRemoveNotAssignedTrustedIdpFromIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
                
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm("trustedidp2realm");
        
        idpDAO.removeTrustedIdpFromIdp(idp, trustedIdp);
    }
    
    
    @Test(expected = NoResultException.class)
    public void testTryRemoveUnknownTrustedIdpFromIdp() {
        Idp idp = new Idp();
        idp.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
                
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm("urn:org:apache:cxf:fediz:UNKNOWN");
        
        idpDAO.removeTrustedIdpFromIdp(idp, trustedIdp);
    }
    */
    
    
    private static Idp createIdp(String realm) throws MalformedURLException {
        Idp idp = new Idp();
        idp.setRealm(realm);
        idp.setCertificate("stsKeystoreA.properties");
        idp.setCertificatePassword("realma");
        idp.setIdpUrl(new URL("https://localhost:9443/fediz-idp/federation"));
        idp.setStsUrl(new URL("https://localhost:9443/fediz-idp-sts/REALMA"));
        idp.setServiceDisplayName("NEW REALM");
        idp.setServiceDescription("IDP of New Realm");
        idp.setUri("realma");
        idp.setProvideIdpList(true);
        Map<String, String> authUris = new HashMap<String, String>();
        authUris.put("default", "/login/default");
        idp.setAuthenticationURIs(authUris);
        List<String> protocols = new ArrayList<String>();
        protocols.add("http://docs.oasis-open.org/wsfed/federation/200706");
        protocols.add("http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        idp.setSupportedProtocols(protocols);
        List<String> tokenTypes = new ArrayList<String>();
        tokenTypes.add(WSConstants.SAML2_NS);
        tokenTypes.add(WSConstants.SAML_NS);
        idp.setTokenTypesOffered(tokenTypes);
        idp.setUseCurrentIdp(true);
        return idp;
    }
    /*
    private static Application createApplication(String realm) {
        Application application = new Application();
        application.setRealm(realm);
        application.setEncryptionCertificate("");
        application.setLifeTime("3600");
        application.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("ApplicationServiceType");
        application.setServiceDescription("Fedizhelloworld description");
        application.setServiceDisplayName("Fedizhelloworld");
        application.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        return application;
    }
    */
    

}
