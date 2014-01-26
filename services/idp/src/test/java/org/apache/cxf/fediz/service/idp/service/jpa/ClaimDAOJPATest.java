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

import java.net.URI;
import java.util.List;

import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.service.ClaimDAO;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.Assert;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:testContext.xml" })
public class ClaimDAOJPATest {

    //@Autowired
    //private IdpDAO idpDAO;
    
    //@Autowired
    //private TrustedIdpDAO trustedIdpDAO;
    
    @Autowired
    private ClaimDAO claimDAO;
    
    
    @BeforeClass
    public static void init() {
        System.setProperty("spring.profiles.active", "jpa");
    }
    
    
    @Test
    public void testReadAllClaims() {
        List<Claim> claims = claimDAO.getClaims(0, 999);
        Assert.isTrue(5 == claims.size(), "Size doesn't match");
    }
    
    @Test
    public void testReadExistingClaim() {
        Claim claim = claimDAO.getClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");
        Assert.isTrue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
                      .equals(claim.getClaimType().toString()),
                      "ClaimType doesn't match");
        Assert.isTrue("firstname".equals(claim.getDisplayName()),
                      "Claim Display name doesn't match");
        Assert.isTrue("Description for firstname".equals(claim.getDescription()),
                      "Claim Description name doesn't match");
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryReadNonexistingClaim() {
        claimDAO.getClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givennamenotexist");
    }
    
    
    @Test
    public void testAddNewClaim() {
        Claim claim5 = new Claim();
        claim5.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/town"));
        claim5.setDisplayName("Town");
        claim5.setDescription("Town Description");
        claimDAO.addClaim(claim5);
        
        List<Claim> claims = claimDAO.getClaims(0, 999);
        Assert.isTrue(6 == claims.size(), "Size doesn't match. Claim not added");
    }
    
    
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingClaim() {
        Claim claim5 = new Claim();
        claim5.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        claim5.setDisplayName("firstname");
        claim5.setDescription("Description for firstname");
        claimDAO.addClaim(claim5);
    }
    
    //[TODO] UpdateClaim
    /*
    @Test
    public void testUpdateIdp() {
        String realm = "urn:org:apache:cxf:fediz:idp:testupdate";
        //Prepare
        Idp idp = createIdp(realm);
        idpDAO.addIdp(idp);
        
        //Testcase
        idp = new Idp();
        idp.setRealm(realm);
        idp.setCertificate("UstsKeystoreA.properties");
        idp.setCertificatePassword("Urealma");
        idp.setIdpUrl("Uhttps://localhost:9443/fediz-idp/federation");
        idp.setStsUrl("Uhttps://localhost:9443/fediz-idp-sts/REALMA");
        idp.setServiceDisplayName("UNEW REALM");
        idp.setServiceDescription("UIDP of New Realm");
        idp.setUri("Urealmn");
        idp.setProvideIDPList(true);
        Map<String, String> authUris = new HashMap<String, String>();
        authUris.put("default", "/login/default");
        idp.setAuthenticationURIs(authUris);
        List<String> protocols = new ArrayList<String>();
        protocols.add("http://docs.oasis-open.org/wsfed/federation/200706");
        idp.setSupportedProtocols(protocols);
        List<String> tokenTypes = new ArrayList<String>();
        tokenTypes.add(WSConstants.SAML2_NS);
        idp.setTokenTypesOffered(tokenTypes);
        idp.setUseCurrentIDP(false);
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
        Assert.isTrue("Uhttps://localhost:9443/fediz-idp/federation".equals(idp.getIdpUrl()),
                      "IdpUrl doesn't match");
        Assert.isTrue("Uhttps://localhost:9443/fediz-idp-sts/REALMA".equals(idp.getStsUrl()),
                      "StsUrl doesn't match");
        Assert.isTrue("Urealmn".equals(idp.getUri()),
                      "Uri doesn't match");
        Assert.isTrue(idp.isProvideIDPList(),
                      "ProvideIDPList doesn't match");
        Assert.isTrue(!idp.isUseCurrentIDP(),
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
     */
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryRemoveUnknownClaim() {
        claimDAO.deleteClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/town/WRONG");
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testRemoveExistingClaim() {
        claimDAO.deleteClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email");
        
        claimDAO.getClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email");
    }
    

}
