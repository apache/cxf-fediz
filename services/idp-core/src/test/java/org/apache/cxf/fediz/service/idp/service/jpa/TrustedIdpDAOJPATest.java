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

import java.util.List;

import org.apache.cxf.fediz.service.idp.domain.FederationType;
import org.apache.cxf.fediz.service.idp.domain.TrustType;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.service.TrustedIdpDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.Assert;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;



@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:testContext.xml" })
public class TrustedIdpDAOJPATest {

    @Autowired
    private TrustedIdpDAO trustedIdpDAO;


    @BeforeClass
    public static void init() {
        System.setProperty("spring.profiles.active", "jpa");
    }


    @Test
    public void testReadAllTrustedIdps() {
        List<TrustedIdp> trustedIdps = trustedIdpDAO.getTrustedIDPs(0, 999);
        Assert.isTrue(2 <= trustedIdps.size(), "Size doesn't match");
    }

    @Test
    public void testReadExistingTrustedIdp() {
        TrustedIdp trustedIdp = trustedIdpDAO.getTrustedIDP("urn:org:apache:cxf:fediz:idp:realm-B");
        Assert.isTrue("realmb.cert".equals(trustedIdp.getCertificate()),
                      "Certificate name doesn't match");
        Assert.isTrue("Realm B description".equals(trustedIdp.getDescription()),
                      "Description name doesn't match");
        Assert.isTrue(FederationType.FEDERATE_IDENTITY.equals(trustedIdp.getFederationType()),
                      "FederationType doesn't match");
        Assert.isTrue("Realm B".equals(trustedIdp.getName()),
                      "Name doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wsfed/federation/200706".equals(trustedIdp.getProtocol()),
                      "Protocol doesn't match");
        Assert.isTrue("urn:org:apache:cxf:fediz:idp:realm-B".equals(trustedIdp.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue(TrustType.PEER_TRUST.equals(trustedIdp.getTrustType()),
                      "TrustType doesn't match");
        Assert.isTrue("https://localhost:12443/fediz-idp-remote/federation".equals(trustedIdp.getUrl()),
                      "Url doesn't match");
        Assert.isTrue(trustedIdp.isCacheTokens(), "CacheTokens doesn't match");
    }


    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryReadNonexistingTrustedIdp() {
        trustedIdpDAO.getTrustedIDP("urn:org:apache:cxf:fediz:idp:NOTEXIST");
    }


    @Test
    public void testAddNewTrustedIdp() {
        String realm = "urn:org:apache:cxf:fediz:trusted-idp:testadd";
        TrustedIdp trustedIdp = createTrustedIdp(realm);
        trustedIdpDAO.addTrustedIDP(trustedIdp);

        trustedIdp = trustedIdpDAO.getTrustedIDP(realm);

        Assert.isTrue("realmb.cert".equals(trustedIdp.getCertificate()),
                      "Certificate name doesn't match");
        Assert.isTrue("Realm B description".equals(trustedIdp.getDescription()),
                      "Description name doesn't match");
        Assert.isTrue(FederationType.FEDERATE_IDENTITY.equals(trustedIdp.getFederationType()),
                      "FederationType doesn't match");
        Assert.isTrue("Realm B".equals(trustedIdp.getName()),
                      "Name doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wsfed/federation/200706".equals(trustedIdp.getProtocol()),
                      "Protocol doesn't match");
        Assert.isTrue(realm.equals(trustedIdp.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue(TrustType.PEER_TRUST.equals(trustedIdp.getTrustType()),
                      "TrustType doesn't match");
        Assert.isTrue("https://localhost:12443/fediz-idp-remote/federation".equals(trustedIdp.getUrl()),
                      "Url doesn't match");
        Assert.isTrue(!trustedIdp.isCacheTokens(), "CacheTokens doesn't match");
    }


    @Test
    public void testUpdateTrustedIdp() {
        String realm = "urn:org:apache:cxf:fediz:trusted-idp:testupdate";
        //Prepare
        TrustedIdp trustedIdp = createTrustedIdp(realm);
        trustedIdpDAO.addTrustedIDP(trustedIdp);

        //Testcase
        trustedIdp = new TrustedIdp();
        trustedIdp.setRealm(realm);
        trustedIdp.setCacheTokens(true);
        trustedIdp.setCertificate("Utrusted cert");
        trustedIdp.setDescription("URealm B description");
        trustedIdp.setFederationType(FederationType.FEDERATE_CLAIMS);
        trustedIdp.setName("URealm B");
        trustedIdp.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        trustedIdp.setTrustType(TrustType.INDIRECT_TRUST);
        trustedIdp.setUrl("Uhttps://localhost:12443/fediz-idp-remote/federation");

        trustedIdpDAO.updateTrustedIDP(realm, trustedIdp);

        trustedIdp = trustedIdpDAO.getTrustedIDP(realm);

        Assert.isTrue("Utrusted cert".equals(trustedIdp.getCertificate()),
                      "Certificate name doesn't match");
        Assert.isTrue("URealm B description".equals(trustedIdp.getDescription()),
                      "Description name doesn't match");
        Assert.isTrue(FederationType.FEDERATE_CLAIMS.equals(trustedIdp.getFederationType()),
                      "FederationType doesn't match");
        Assert.isTrue("URealm B".equals(trustedIdp.getName()),
                      "Name doesn't match");
        Assert.isTrue("http://docs.oasis-open.org/wsfed/federation/200706".equals(trustedIdp.getProtocol()),
                      "Protocol doesn't match");
        Assert.isTrue(realm.equals(trustedIdp.getRealm()),
                      "Realm doesn't match");
        Assert.isTrue(TrustType.INDIRECT_TRUST.equals(trustedIdp.getTrustType()),
                      "TrustType doesn't match");
        Assert.isTrue("Uhttps://localhost:12443/fediz-idp-remote/federation".equals(trustedIdp.getUrl()),
                      "Url doesn't match");
        Assert.isTrue(trustedIdp.isCacheTokens(), "CacheTokens doesn't match");

    }


    @Test(expected = DataIntegrityViolationException.class)
    public void testTryAddExistingTrustedIdp() {
        TrustedIdp trustedIdp = createTrustedIdp("urn:org:apache:cxf:fediz:idp:realm-B");
        trustedIdpDAO.addTrustedIDP(trustedIdp);
    }


    @Test(expected = EmptyResultDataAccessException.class)
    public void testTryRemoveUnknownTrustedIdp() {
        trustedIdpDAO.deleteTrustedIDP("urn:org:apache:cxf:fediz:trusted-idp:NOTEXIST");
    }


    @Test(expected = EmptyResultDataAccessException.class)
    public void testRemoveExistingTrustedIdp() {
        String realm = "urn:org:apache:cxf:fediz:trusted-idp:testdelete";
        TrustedIdp trustedIdp = createTrustedIdp(realm);

        trustedIdpDAO.addTrustedIDP(trustedIdp);

        trustedIdpDAO.deleteTrustedIDP(realm);

        trustedIdpDAO.getTrustedIDP(realm);
    }


    private static TrustedIdp createTrustedIdp(String realm) {
        TrustedIdp trustedIdp = new TrustedIdp();
        trustedIdp.setRealm(realm);
        trustedIdp.setCacheTokens(false);
        trustedIdp.setCertificate("realmb.cert");
        trustedIdp.setDescription("Realm B description");
        trustedIdp.setFederationType(FederationType.FEDERATE_IDENTITY);
        trustedIdp.setName("Realm B");
        trustedIdp.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
        trustedIdp.setTrustType(TrustType.PEER_TRUST);
        trustedIdp.setUrl("https://localhost:12443/fediz-idp-remote/federation");
        return trustedIdp;
    }


}
