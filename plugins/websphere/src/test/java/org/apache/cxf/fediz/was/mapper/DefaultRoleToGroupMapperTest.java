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

package org.apache.cxf.fediz.was.mapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 */
public class DefaultRoleToGroupMapperTest {

    @Test
    public void testSimpleMapping() {
        DefaultRoleToGroupMapper mapper = new DefaultRoleToGroupMapper();

        List<String> result = mapper.groupsFromRoles(Arrays.asList("Role1", "Role2", "Role3"));
        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals("Role1", result.get(0));
        assertEquals("Role3", result.get(2));
    }

    @Test
    public void testNullMapping() {
        DefaultRoleToGroupMapper mapper = new DefaultRoleToGroupMapper();

        List<String> result = mapper.groupsFromRoles(null);
        assertNull(result);
    }

    @Test
    public void testEmptyMapping() {
        DefaultRoleToGroupMapper mapper = new DefaultRoleToGroupMapper();

        List<String> result = mapper.groupsFromRoles(new ArrayList<String>());
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testTemplateMapping() {
        DefaultRoleToGroupMapper mapper = new DefaultRoleToGroupMapper();
        Properties props = new Properties();
        props.put(DefaultRoleToGroupMapper.PROPERTY_KEY_ROLE_MAPPING_TEMPLATE,
                  DefaultRoleToGroupMapper.DEFAULT_MAPPING_TEMPLATE);
        mapper.initialize(props);

        List<String> result = mapper.groupsFromRoles(Arrays.asList("Role1", "Role2", "Role3"));
        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals("group:defaultWIMFileBasedRealm/Role1", result.get(0));
    }
}
