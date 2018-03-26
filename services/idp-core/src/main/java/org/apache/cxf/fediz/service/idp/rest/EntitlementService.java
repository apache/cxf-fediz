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
import org.springframework.security.access.prepost.PreAuthorize;


@Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
@Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
@Path("entitlements")
public interface EntitlementService {

    @GET
    @PreAuthorize("hasRole('ENTITLEMENT_LIST')")
    Entitlements getEntitlements(@QueryParam("start") int start,
                                 @QueryParam("size") @DefaultValue("5") int size,
                                 @Context UriInfo uriInfo);

    @GET
    @Path("{name}")
    @PreAuthorize("hasRole('ENTITLEMENT_READ')")
    Entitlement getEntitlement(@PathParam("name") String name);

    @POST
    @PreAuthorize("hasRole('ENTITLEMENT_CREATE')")
    Response addEntitlement(@Context UriInfo ui, Entitlement entitlement);

    @PUT
    @Path("{name}")
    @PreAuthorize("hasRole('ENTITLEMENT_UPDATE')")
    Response updateEntitlement(@Context UriInfo ui, @PathParam("name") String name, Entitlement entitlement);

    @DELETE
    @Path("{name}")
    @PreAuthorize("hasRole('ENTITLEMENT_DELETE')")
    Response deleteEntitlement(@PathParam("name") String name);


}
