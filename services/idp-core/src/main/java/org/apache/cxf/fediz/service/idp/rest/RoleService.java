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

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.domain.Role;

import org.springframework.security.access.prepost.PreAuthorize;


@Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
@Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
@Path("roles")
public interface RoleService {

    @GET
    @PreAuthorize("hasRole('ROLE_LIST')")
    Roles getRoles(@QueryParam("start") int start,
                                 @QueryParam("size") @DefaultValue("2") int size,
                                 @QueryParam("expand") @DefaultValue("all")  List<String> expand,
                                 @Context UriInfo uriInfo);

    @GET
    @Path("{name}")
    @PreAuthorize("hasRole('ROLE_CREATE')")
    Role getRole(@PathParam("name") String realm,
                               @QueryParam("expand") @DefaultValue("all")  List<String> expand);

    @POST
    @PreAuthorize("hasRole('ROLE_CREATE')")
    Response addRole(@Context UriInfo ui, Role role);

    @PUT
    @Path("{name}")
    @PreAuthorize("hasRole('ROLE_UPDATE')")
    Response updateRole(@Context UriInfo ui, @PathParam("name") String name, Role role);

    @DELETE
    @Path("{name}")
    @PreAuthorize("hasRole('ROLE_DELETE')")
    Response deleteRole(@PathParam("name") String name);

    @POST
    @Path("{name}/entitlements")
    @PreAuthorize("hasRole('ROLE_UPDATE')")
    Response addEntitlementToRole(@Context UriInfo ui, @PathParam("name") String name, Entitlement entitlement);

    @DELETE
    @Path("{name}/entitlements/{entitlementName}")
    @PreAuthorize("hasRole('ROLE_UPDATE')")
    Response removeEntitlementFromRole(@Context UriInfo ui, @PathParam("name") String name,
                                        @PathParam("entitlementName") String entitlementName);

}
