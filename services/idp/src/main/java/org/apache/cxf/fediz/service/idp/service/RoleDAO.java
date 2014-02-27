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

package org.apache.cxf.fediz.service.idp.service;

import java.util.List;

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.domain.Role;

public interface RoleDAO {

    List<Role> getRoles(int start, int size, List<String> expand);

    Role getRole(String name, List<String> expand);

    Role addRole(Role role);

    void updateRole(String realm, Role role);

    void deleteRole(String name);

    void addEntitlementToRole(Role role, Entitlement entitlement);
    
    void removeEntitlementFromRole(Role role, Entitlement entitlement);

}
