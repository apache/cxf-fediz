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
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class DefaultRoleToGroupMapper implements RoleToGroupMapper {

    public static final String PROPERTY_KEY_ROLE_MAPPING_TEMPLATE = "roleMappingTemplate";

    public static final String ROLE_MAPPING_PLACEHOLDER = "%roleName%";

    public static final String DEFAULT_MAPPING_TEMPLATE = "group:defaultWIMFileBasedRealm/"
                                                          + DefaultRoleToGroupMapper.ROLE_MAPPING_PLACEHOLDER;

    private static final Logger LOG = LoggerFactory.getLogger(DefaultRoleToGroupMapper.class);

    private String template;

    @Override
    public void cleanup() {
    }

    @Override
    public List<String> groupsFromRoles(List<String> roles) {
        if (template == null || roles == null) {
            return roles;
        } else {
            List<String> renamedRoles = new ArrayList<>();
            for (String role : roles) {
                String renamedRole = template.replace(ROLE_MAPPING_PLACEHOLDER, role);
                renamedRoles.add(renamedRole);
                LOG.debug("Mapped role {} to {}", role, renamedRole);
            }
            return renamedRoles;
        }
    }

    @Override
    public void initialize(Properties properties) {
        if (properties != null && properties.containsKey(PROPERTY_KEY_ROLE_MAPPING_TEMPLATE)) {
            template = properties.getProperty(PROPERTY_KEY_ROLE_MAPPING_TEMPLATE);
            LOG.info("Set RoleToGroup regex pattern: {}", template);
        } else {
            template = null;
        }
    }

}
