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
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.RequestClaim;
import org.apache.cxf.fediz.service.idp.service.ApplicationDAO;
import org.apache.cxf.fediz.service.idp.service.ClaimDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ApplicationServiceImpl implements ApplicationService {

    private static final Logger LOG = LoggerFactory
            .getLogger(ApplicationServiceImpl.class);

    @Autowired
    private ApplicationDAO applicationDAO;
    
    @Autowired
    private ClaimDAO claimDAO;
           
    @Override
    public Applications getApplications(int start, int size, List<String> expand, UriInfo uriInfo) {
        List<Application> applications = applicationDAO.getApplications(start, size, expand);
        
        for (Application a : applications) {
            URI self = uriInfo.getAbsolutePathBuilder().path(a.getRealm()).build();
            a.setHref(self);
        }
        
        Applications list = new Applications();
        list.setApplications(applications);
        return list;
    }
    
    @Override
    public Application getApplication(String realm, List<String> expand) {
        Application application = applicationDAO.getApplication(realm, expand);
        if (application == null) {
            throw new NotFoundException();
        } else {
            return application;
        }
    }
    
    @Override
    public Response addApplication(UriInfo ui, Application application) {
        LOG.info("add Service config");
        if (application.getRequestedClaims() != null && application.getRequestedClaims().size() > 0) {
            LOG.warn("Application resource contains sub resource 'claims'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        Application createdApplication = applicationDAO.addApplication(application);
        
        UriBuilder uriBuilder = UriBuilder.fromUri(ui.getRequestUri());
        uriBuilder.path("{index}");
        URI location = uriBuilder.build(createdApplication.getRealm());
        return Response.created(location).entity(application).build();
    }
    
    @Override
    public Response updateApplication(UriInfo ui, String realm, Application application) {
        if (!realm.equals(application.getRealm().toString())) {
            throw new ValidationException(Status.BAD_REQUEST);
        }
        if (application.getRequestedClaims() != null && application.getRequestedClaims().size() > 0) {
            LOG.warn("Application resource contains sub resource 'claims'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        applicationDAO.updateApplication(realm, application);
        
        return Response.noContent().build();
    }
 
    @Override
    public Response deleteApplication(String realm) {
        applicationDAO.deleteApplication(realm);
        
        return Response.noContent().build();
    }
    
    @Override
    public Response addClaimToApplication(UriInfo ui, String realm, RequestClaim claim) {
        Application application = applicationDAO.getApplication(realm, null);
        if (application.getRequestedClaims().contains(claim)) {
            LOG.warn("Claim '" + claim.getClaimType() + "' already added");
            //[TODO] Status.CONFLICT correct if the relation to with Claim already exists
            throw new WebApplicationException(Status.CONFLICT);
        }
        Claim foundClaim = claimDAO.getClaim(claim.getClaimType().toString());
        RequestClaim rc = new RequestClaim(foundClaim);
        application.getRequestedClaims().add(rc);
        applicationDAO.updateApplication(realm, application);
        
        return Response.noContent().build();
    }
    
    @Override
    public Response removeClaimFromApplication(UriInfo ui, String realm,  String claimType) {
        Application application = applicationDAO.getApplication(realm, null);
        
        RequestClaim foundItem = null; 
        for (RequestClaim item : application.getRequestedClaims()) {
            if (item.getClaimType().toString().equals(claimType)) {
                foundItem = item;
                break;
            }
        }
        if (foundItem == null) {
            LOG.warn("Claim '" + claimType + "' not found");
            throw new WebApplicationException(Status.NOT_FOUND);
        }
        application.getRequestedClaims().remove(foundItem);
        applicationDAO.updateApplication(realm, application);
        
        return Response.noContent().build();
    }
}