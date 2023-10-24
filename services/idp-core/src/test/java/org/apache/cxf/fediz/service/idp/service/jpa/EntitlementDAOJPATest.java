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

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.service.EntitlementDAO;
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
public class EntitlementDAOJPATest {

    @Autowired
    private EntitlementDAO entitlementDAO;


    @BeforeAll
    public static void init() {
        System.setProperty("spring.profiles.active", "jpa");
    }


    @Test
    public void testReadAllEntitlements() {
        List<Entitlement> entitlements = entitlementDAO.getEntitlements(0, 999);
        Assert.isTrue(30 == entitlements.size(), "Size doesn't match");
    }

    @Test
    public void testReadExistingEntitlement() {
        Entitlement entitlement = entitlementDAO.getEntitlement("CLAIM_LIST");
        Assert.isTrue("CLAIM_LIST".equals(entitlement.getName()),
                      "Entitlement name doesn't match");
        Assert.isTrue("Description for CLAIM_LIST".equals(entitlement.getDescription()),
                      "Entitlement Description doesn't match");
    }


    @Test
    public void testTryReadNonexistingEntitlement() {
        Assertions.assertThrows(EmptyResultDataAccessException.class, () -> {
            entitlementDAO.getEntitlement("CLAIM_NOT_EXIST");
        });
    }


    @Test
    public void testAddNewEntitlement() {
        Entitlement entitlement5 = new Entitlement();
        entitlement5.setName("GUGUS_CREATE");
        entitlement5.setDescription("Any entitlement");
        entitlementDAO.addEntitlement(entitlement5);

        List<Entitlement> entitlements = entitlementDAO.getEntitlements(0, 999);
        Assert.isTrue(31 == entitlements.size(), "Size doesn't match. Entitlement not added");
    }


    @Test
    public void testTryAddExistingEntitlement() {
        Assertions.assertThrows(DataIntegrityViolationException.class, () -> {
            Entitlement entitlement5 = new Entitlement();
            entitlement5.setName("CLAIM_DELETE");
            entitlement5.setDescription("Description for CLAIM_DELETE");
            entitlementDAO.addEntitlement(entitlement5);
        });
    }


    @Test
    public void testTryRemoveUnknownEntitlement() {
        Assertions.assertThrows(EmptyResultDataAccessException.class, () -> {
            entitlementDAO.deleteEntitlement("GUGUS_NOT_EXIST");
        });
    }


    @Test
    public void testRemoveExistingEntitlement() {
        Assertions.assertThrows(EmptyResultDataAccessException.class, () -> {
            Entitlement entitlement5 = new Entitlement();
            entitlement5.setName("CLAIM_TO_DELETE");
            entitlement5.setDescription("Description for CLAIM_TO_DELETE");
            entitlementDAO.addEntitlement(entitlement5);

            entitlementDAO.deleteEntitlement("CLAIM_TO_DELETE");

            entitlementDAO.getEntitlement("CLAIM_TO_DELETE");
        });
    }


}
