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

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;


public class RootServiceImpl implements RootService {

    public RootServiceImpl() {
    }
    
    public Response head(UriInfo uriInfo) {
        UriBuilder absolute = uriInfo.getBaseUriBuilder();
        URI claimUrl = absolute.clone().path("claims").build();
        URI idpUrl = absolute.clone().path("idps").build();
        URI applicationUrl = absolute.clone().path("applications").build();
        URI trustedIdpUrl = absolute.clone().path("trusted-idps").build();
        javax.ws.rs.core.Link claims = javax.ws.rs.core.Link.fromUri(claimUrl).rel("claims")
            .type("application/xml").build();
        javax.ws.rs.core.Link idps = javax.ws.rs.core.Link.fromUri(idpUrl).rel("idps")
            .type("application/xml").build();
        javax.ws.rs.core.Link applications = javax.ws.rs.core.Link.fromUri(applicationUrl).rel("applications")
            .type("application/xml").build();
        javax.ws.rs.core.Link trustedIdps = javax.ws.rs.core.Link.fromUri(trustedIdpUrl).rel("trusted-idps")
            .type("application/xml").build();

        Response.ResponseBuilder builder = Response.ok().links(claims, idps, applications, trustedIdps);
        return builder.build();
    }

}