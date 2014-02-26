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
import java.util.Arrays;
import java.util.List;


import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.RequestClaim;
import org.apache.cxf.fediz.service.idp.service.ApplicationDAO;

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
public class ApplicationDAOJPATest {

    @Autowired
    private ApplicationDAO applicationDAO;
    
    
    @BeforeClass
    public static void init() {
        System.setProperty("spring.profiles.active", "jpa");
    }
    
    
    @Test
    public void testReadAllApplications() {
        List<Application> applications = applicationDAO.getApplications(0, 999, null);
        // Application could have been removed, Order not given as per JUnit design
        Assert.isTrue(1 < applications.size(), "Size doesn't match [" + applications.size() + "]");
    }
    
    
    @Test
    public void testReadExistingApplicationEmbeddedAll() {
        Application application = applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld",
                                                                Arrays.asList("all"));
        
        Assert.isTrue("3600".equals(application.getLifeTime()),
                      "LifeTime doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wsfed/federation/200706".equals(application.getProtocol()),
                      "Protocol doesn't match");
        Assert.isTrue("urn:org:apache:cxf:fediz:fedizhelloworld".equals(application.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue("ApplicationServiceType".equals(application.getRole()),
                      "Role doesn't match");
        Assert.isTrue("Web Application to illustrate WS-Federation".equals(application.getServiceDescription()),
                      "ServiceDescription doesn't match");
        Assert.isTrue("Fedizhelloworld".equals(application.getServiceDisplayName()),
                      "ServiceDisplayName doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
                      .equals(application.getTokenType()),
                      "TokenType doesn't match");
        Assert.isTrue(4 == application.getRequestedClaims().size(),
                      "Number of claims doesn't match [" + application.getRequestedClaims().size() + "]");
    }
    
    @Test
    public void testReadExistingApplicationEmbeddedClaims() {
        Application application = applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld",
                                                                Arrays.asList("claims"));
        
        Assert.isTrue(4 == application.getRequestedClaims().size(),
                      "Number of claims doesn't match");
    }
    
    @Test
    public void testReadExistingApplicationEmbeddedNull() {
        Application application = applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld",
                                                                null);
        
        Assert.isTrue(0 == application.getRequestedClaims().size(),
                      "Number of claims doesn't match");
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryReadNonexistingApplication() {
        applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld:NOTEXIST", null);
    }
    
    
    @Test
    public void testAddNewApplication() {
        
        String realm = "urn:org:apache:cxf:fediz:application:testaddnew";
        Application application = createApplication(realm);
        applicationDAO.addApplication(application);
        
        application = applicationDAO.getApplication(realm, null);
        
        Assert.isTrue("".equals(application.getEncryptionCertificate()),
                      "EncryptionCertificate doesn't match");
        Assert.isTrue("3600".equals(application.getLifeTime()),
                      "LifeTime doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wsfed/federation/200706".equals(application.getProtocol()),
                      "Protocol doesn't match");
        Assert.isTrue(realm.equals(application.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue("ApplicationServiceType".equals(application.getRole()),
                      "Role doesn't match");
        Assert.isTrue("Fedizhelloworld2 description".equals(application.getServiceDescription()),
                      "ServiceDescription doesn't match");
        Assert.isTrue("Fedizhelloworld2".equals(application.getServiceDisplayName()),
                      "ServiceDisplayName doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
                      .equals(application.getTokenType()),
                      "TokenType doesn't match");
        Assert.isTrue("http://www.w3.org/ns/ws-policy"
                      .equals(application.getPolicyNamespace()),
                      "Policy Namespace doesn't match");
        Assert.isTrue(0 == application.getRequestedClaims().size(),
                      "Number of claims doesn't match");
    }
    
    @Test
    public void testUpdateApplication() {
        String realm = "urn:org:apache:cxf:fediz:application:testupdate";
        
        //Prepare
        Application application = createApplication(realm);
        applicationDAO.addApplication(application);
        
        //Testcase
        application = new Application();
        application.setRealm(realm);
        application.setEncryptionCertificate("U");
        application.setLifeTime("U3600");
        application.setProtocol("Uhttp://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("UApplicationServiceType");
        application.setServiceDescription("UFedizhelloworld2 description");
        application.setServiceDisplayName("UFedizhelloworld2");
        application.setTokenType("Uhttp://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1");
        application.setPolicyNamespace("Uhttp://www.w3.org/ns/ws-policy");
        
        Assert.isTrue("U".equals(application.getEncryptionCertificate()),
                      "EncryptionCertificate doesn't match");
        Assert.isTrue("U3600".equals(application.getLifeTime()),
                      "LifeTime doesn't match");
        Assert.isTrue("Uhttp://docs.oasis-open.org/wsfed/federation/200706".equals(application.getProtocol()),
                      "Protocol doesn't match");
        Assert.isTrue(realm.equals(application.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue("UApplicationServiceType".equals(application.getRole()),
                      "Role doesn't match");
        Assert.isTrue("UFedizhelloworld2 description".equals(application.getServiceDescription()),
                      "ServiceDescription doesn't match");
        Assert.isTrue("UFedizhelloworld2".equals(application.getServiceDisplayName()),
                      "ServiceDisplayName doesn't match");
        Assert.isTrue("Uhttp://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
                      .equals(application.getTokenType()),
                      "TokenType doesn't match");
        Assert.isTrue("Uhttp://www.w3.org/ns/ws-policy"
                      .equals(application.getPolicyNamespace()),
                      "Policy Namespace doesn't match");
        Assert.isTrue(0 == application.getRequestedClaims().size(),
                      "Number of claims doesn't match");
    }
    
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingApplication() {
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
        application.setEncryptionCertificate("");
        application.setLifeTime("3600");
        application.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("ApplicationServiceType");
        application.setServiceDescription("Fedizhelloworld description");
        application.setServiceDisplayName("Fedizhelloworld");
        application.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        
        applicationDAO.addApplication(application);
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryRemoveUnknownApplication() {
        applicationDAO.deleteApplication("urn:org:apache:cxf:fediz:fedizhelloworld:NOTEXIST");
    }
    
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testRemoveExistingApplication() {
        String realm = "urn:org:apache:cxf:fediz:app:testdelete";
        Application application = new Application();
        application.setRealm(realm);
        applicationDAO.addApplication(application);
        
        applicationDAO.deleteApplication(realm);
        
        applicationDAO.getApplication(realm, null);
    }
    
    @Test
    public void testAddClaimToApplication() {
        //Prepare step
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld:testaddclaim");
        application.setEncryptionCertificate("");
        application.setLifeTime("3600");
        application.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("ApplicationServiceType");
        application.setServiceDescription("Fedizhelloworld description");
        application.setServiceDisplayName("Fedizhelloworld");
        application.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        
        applicationDAO.addApplication(application);
        
        //Testcase
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        
        applicationDAO.addClaimToApplication(application, requestClaim);
               
        application = applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld:testaddclaim",
                                                    Arrays.asList("all"));
        
        Assert.isTrue(1 == application.getRequestedClaims().size(), "requestedClaims size doesn't match");
    }
    
    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingClaimToApplication() {
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
        
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        
        applicationDAO.addClaimToApplication(application, requestClaim);
    }
    
    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryAddUnknownClaimToApplication() {
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
        
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/UNKOWN"));
        
        applicationDAO.addClaimToApplication(application, requestClaim);
    }
    
    
    @Test
    public void testRemoveClaimFromApplication() {
        //Prepare step
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld:testremoveclaim");
        application.setEncryptionCertificate("");
        application.setLifeTime("3600");
        application.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("ApplicationServiceType");
        application.setServiceDescription("Fedizhelloworld description");
        application.setServiceDisplayName("Fedizhelloworld");
        application.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        
        applicationDAO.addApplication(application);
        
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
        
        applicationDAO.addClaimToApplication(application, requestClaim);
               
        application = applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld:testremoveclaim",
                                                    Arrays.asList("all"));
        Assert.isTrue(1 == application.getRequestedClaims().size(), "requestedClaims size doesn't match");
        
        //Testcase
        applicationDAO.removeClaimFromApplication(application, requestClaim);
        application = applicationDAO.getApplication("urn:org:apache:cxf:fediz:fedizhelloworld:testremoveclaim",
                                                    Arrays.asList("all"));
        Assert.isTrue(0 == application.getRequestedClaims().size(), "requestedClaims size doesn't match");
    }
    
    @Test(expected = JpaObjectRetrievalFailureException.class)
    public void testTryRemoveNotAssignedClaimFromApplication() {
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
                
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/city"));
        
        applicationDAO.removeClaimFromApplication(application, requestClaim);
    }
    
    @Test(expected = JpaObjectRetrievalFailureException.class)
    public void testTryRemoveUnknownClaimFromApplication() {
        Application application = new Application();
        application.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
                
        RequestClaim requestClaim = new RequestClaim();
        requestClaim.setOptional(false);
        requestClaim.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/UNKNOWN"));
        
        applicationDAO.removeClaimFromApplication(application, requestClaim);
    }
    
    private static Application createApplication(String realm) {
        Application application = new Application();
        application.setRealm(realm);
        application.setEncryptionCertificate("");
        application.setLifeTime("3600");
        application.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        application.setRole("ApplicationServiceType");
        application.setServiceDescription("Fedizhelloworld2 description");
        application.setServiceDisplayName("Fedizhelloworld2");
        application.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1");
        application.setPolicyNamespace("http://www.w3.org/ns/ws-policy");
        return application;
    }

}
