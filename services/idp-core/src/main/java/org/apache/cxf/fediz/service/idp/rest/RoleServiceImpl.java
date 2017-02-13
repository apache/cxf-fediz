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

package org.apache.cxf.fediz.service.idp.rest;

import java.net.URI;
import java.util.List;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.domain.Role;
import org.apache.cxf.fediz.service.idp.service.EntitlementDAO;
import org.apache.cxf.fediz.service.idp.service.RoleDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RoleServiceImpl implements RoleService {

    private static final Logger LOG = LoggerFactory
            .getLogger(RoleServiceImpl.class);

    @Autowired
    private RoleDAO roleDAO;

    @Autowired
    private EntitlementDAO entitlementDAO;

    @Override
    public Roles getRoles(int start, int size, List<String> expand, UriInfo uriInfo) {
        List<Role> roles = roleDAO.getRoles(start, size, expand);

        Roles list = new Roles();
        list.setRoles(roles);
        return list;
    }

    @Override
    public Role getRole(String name, List<String> expand) {
        Role role = roleDAO.getRole(name, expand);
        if (role == null) {
            throw new NotFoundException();
        } else {
            return role;
        }
    }

    @Override
    public Response addRole(UriInfo ui, Role role) {
        if (role.getEntitlements() != null && role.getEntitlements().size() > 0) {
            LOG.warn("Role resource contains sub resource 'entitlements'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        Role createdRole = roleDAO.addRole(role);

        UriBuilder uriBuilder = UriBuilder.fromUri(ui.getRequestUri());
        uriBuilder.path("{index}");
        URI location = uriBuilder.build(createdRole.getName());

        LOG.debug("Role '" + role.getName() + "' added");
        return Response.created(location).entity(role).build();
    }

    @Override
    public Response updateRole(UriInfo ui, String name, Role role) {
        if (!name.equals(role.getName().toString())) {
            throw new BadRequestException();
        }
        if (role.getEntitlements() != null && role.getEntitlements().size() > 0) {
            LOG.warn("Role resource contains sub resource 'entitlements'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        roleDAO.updateRole(name, role);

        LOG.debug("Role '" + role.getName() + "' updated");
        return Response.noContent().build();
    }

    @Override
    public Response deleteRole(String name) {
        roleDAO.deleteRole(name);

        LOG.debug("Role '" + name + "' deleted");
        return Response.noContent().build();
    }

    @Override
    public Response addEntitlementToRole(UriInfo ui, String name, Entitlement entitlement) {
        Role role = roleDAO.getRole(name, null);

        Entitlement foundEntitlement = entitlementDAO.getEntitlement(entitlement.getName());
        roleDAO.addEntitlementToRole(role, foundEntitlement);

        LOG.debug("Entitlement '" + entitlement.getName() + "' added to Role '" + name + "'");
        return Response.noContent().build();
    }

    @Override
    public Response removeEntitlementFromRole(UriInfo ui, String name, String entitlementName) {
        Role role = roleDAO.getRole(name, null);
        Entitlement entitlement = entitlementDAO.getEntitlement(entitlementName);

        roleDAO.removeEntitlementFromRole(role, entitlement);

        LOG.debug("Entitlement '" + entitlementName + "' removed from Role '" + name + "'");
        return Response.noContent().build();
    }

}