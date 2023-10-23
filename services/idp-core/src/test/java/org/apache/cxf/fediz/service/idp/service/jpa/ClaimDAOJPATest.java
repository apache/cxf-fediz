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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.Assert;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;


@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = { "classpath:testContext.xml" })
public class ClaimDAOJPATest {

    @Autowired
    private ClaimDAO claimDAO;


    @BeforeAll
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


    @Test
    public void testTryReadNonexistingClaim() {
        Assertions.assertThrows(EmptyResultDataAccessException.class, () -> {
            claimDAO.getClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givennamenotexist");
        });
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


    @Test
    public void testTryAddExistingClaim() {
        Assertions.assertThrows(DataIntegrityViolationException.class, () -> {
            Claim claim5 = new Claim();
            claim5.setClaimType(URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
            claim5.setDisplayName("firstname");
            claim5.setDescription("Description for firstname");
            claimDAO.addClaim(claim5);
        });
    }


    @Test
    public void testTryRemoveUnknownClaim() {
        Assertions.assertThrows(EmptyResultDataAccessException.class, () -> {
            claimDAO.deleteClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/town/WRONG");
        });
    }


    @Test
    public void testRemoveExistingClaim() {
        Assertions.assertThrows(EmptyResultDataAccessException.class, () -> {
            claimDAO.deleteClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email");

            claimDAO.getClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email");
        });
    }


}
