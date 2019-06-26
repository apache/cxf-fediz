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

import java.security.Principal;

import org.apache.cxf.fediz.service.sts.realms.RealmExtensionIdentityMapper;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * A test implementation of IdentityMapper.
 */
public class RealmExtensionIdentityMapperTest {

    @Test
    public void testDefaultDelimiterInitialization() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        assertEquals(RealmExtensionIdentityMapper.DEFAULT_DELIMITER, im.getDelimiter());
    }

    @Test
    public void testRealmMappingSimpleUser() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        Principal result = im.mapPrincipal("realm-a", new CustomTokenPrincipal("user"), "realm-b");
        assertNotNull(result);
        assertEquals("user@realm-b", result.getName());
    }

    @Test
    public void testRealmMappingComplexUser() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        Principal result = im.mapPrincipal("realm-a", new CustomTokenPrincipal("user.name@realm-a"), "realm-b");
        assertNotNull(result);
        assertEquals("user.name@realm-b", result.getName());
    }

    @Test
    public void testRealmMappingComplexFakeUser() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        Principal result = im.mapPrincipal("realm-a", new CustomTokenPrincipal("user-name@realm-a@test"), "realm-b");
        assertNotNull(result);
        assertEquals("user-name@realm-b", result.getName());
    }

    @Test
    public void testRealmMappingNullUser() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        Principal result = im.mapPrincipal("realm-a", null, "realm-b");
        assertNull(result);
    }

    @Test
    public void testRealmMappingEmptyUserName() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        Principal result = im.mapPrincipal("realm-a", new CustomTokenPrincipal("@realm-a"), "realm-b");
        assertNotNull(result);
        assertEquals("@realm-b", result.getName());
    }

    @Test
    public void testRealmMappingCustomDelimiter() {
        RealmExtensionIdentityMapper im = new RealmExtensionIdentityMapper();
        im.setDelimiter(".");
        Principal result = im.mapPrincipal("realm-a", new CustomTokenPrincipal("pre.fix@realm-a"), "realm-b");
        assertNotNull(result);
        assertEquals("pre.realm-b", result.getName());
    }
}
