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

import javax.ws.rs.NotFoundException;
import javax.ws.rs.ValidationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.service.ClaimDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ClaimServiceImpl implements ClaimService {

    private static final Logger LOG = LoggerFactory
            .getLogger(ClaimServiceImpl.class);

    @Autowired
    private ClaimDAO claimDAO;

    @Override
    public Response getClaims(int start, int size, UriInfo uriInfo) {
        List<Claim> claims = claimDAO.getClaims(start, size);
        
        for (Claim c : claims) {
            URI self = uriInfo.getAbsolutePathBuilder().path(c.getClaimType().toString()).build();
            c.setHref(self);
        }
        
        Claims list = new Claims();
        list.setClaims(claims);
        
        
        //return Response.ok(list).type(MediaType.APPLICATION_JSON_TYPE).build();
        return Response.ok(list).build();
    }
    
    @Override
    public Response addClaim(UriInfo ui, Claim claim) {
        LOG.info("add Claim config");
        
        Claim createdClaim = claimDAO.addClaim(claim);
        
        UriBuilder uriBuilder = UriBuilder.fromUri(ui.getRequestUri());
        uriBuilder.path("{index}");
        URI location = uriBuilder.build(createdClaim.getClaimType().toString());
        return Response.created(location).entity(claim).build();
    }
    
    @Override
    public Claim getClaim(String claimType) {
        Claim claim = claimDAO.getClaim(claimType);
        if (claim == null) {
            throw new NotFoundException();
        } else {
            return claim;
        }
    }

    @Override
    public Response updateClaim(UriInfo ui, String claimType, Claim claim) {
        if (!claimType.equals(claim.getClaimType().toString())) {
            throw new ValidationException(Status.BAD_REQUEST);
        }
        claimDAO.updateClaim(claimType, claim);
        
        return Response.noContent().build();
    }

    @Override
    public Response deleteClaim(String claimType) {
        claimDAO.deleteClaim(claimType);
        
        return Response.noContent().build();
    }
           
    


}