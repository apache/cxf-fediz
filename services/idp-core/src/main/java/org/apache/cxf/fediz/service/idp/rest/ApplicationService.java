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

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.RequestClaim;

import org.springframework.security.access.prepost.PreAuthorize;


@Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
@Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
@Path("applications")
public interface ApplicationService {

    @GET
    @PreAuthorize("hasRole('APPLICATION_LIST')")
    Applications getApplications(@QueryParam("start") int start,
                                 @QueryParam("size") @DefaultValue("2") int size,
                                 @QueryParam("expand") @DefaultValue("all")  List<String> expand,
                                 @Context UriInfo uriInfo);

    @GET
    @Path("{realm}")
    @PreAuthorize("hasRole('APPLICATION_LIST')")
    Application getApplication(@PathParam("realm") String realm,
                               @QueryParam("expand") @DefaultValue("all")  List<String> expand);

    @POST
    @PreAuthorize("hasRole('APPLICATION_CREATE')")
    Response addApplication(@Context UriInfo ui, Application service);
    
    @PUT
    @Path("{realm}")
    @PreAuthorize("hasRole('APPLICATION_UPDATE')")
    Response updateApplication(@Context UriInfo ui, @PathParam("realm") String realm, Application application);
    
    @DELETE
    @Path("{realm}")
    @PreAuthorize("hasRole('APPLICATION_DELETE')")
    Response deleteApplication(@PathParam("realm") String realm);
    
    @POST
    @Path("{realm}/claims")
    @PreAuthorize("hasRole('APPLICATION_UPDATE')")
    Response addClaimToApplication(@Context UriInfo ui, @PathParam("realm") String realm, RequestClaim claim);
    
    @DELETE
    @Path("{realm}/claims/{claimType}")
    @PreAuthorize("hasRole('APPLICATION_UPDATE')")
    Response removeClaimFromApplication(@Context UriInfo ui, @PathParam("realm") String realm,
                                        @PathParam("claimType") String claimType);

}
