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
import java.util.Arrays;
import java.util.List;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.service.ApplicationDAO;
import org.apache.cxf.fediz.service.idp.service.ClaimDAO;
import org.apache.cxf.fediz.service.idp.service.IdpDAO;
import org.apache.cxf.fediz.service.idp.service.TrustedIdpDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class IdpServiceImpl implements IdpService {

    private static final Logger LOG = LoggerFactory
            .getLogger(IdpServiceImpl.class);

    @Autowired
    private IdpDAO idpDAO;
    
    @Autowired
    private ApplicationDAO applicationDAO;
    
    @Autowired
    private TrustedIdpDAO trustedIdpDAO;
    
    @Autowired
    private ClaimDAO claimDAO;
           
    @Override
    public Idps getIdps(int start, int size, List<String> expand, UriInfo uriInfo) {
        List<Idp> idps = idpDAO.getIdps(start, size, expand);
        
        Idps list = new Idps();
        list.setIdps(idps);
        return list;
    }
    
    @Override
    public Idp getIdp(String realm, List<String> expand) {
        Idp idp = idpDAO.getIdp(realm, expand);
        if (idp == null) {
            LOG.warn("IdP not found for realm {}", realm);
            throw new NotFoundException();
        } else {
            return idp;
        }
    }
    
    @Override
    public Response addIdp(UriInfo ui, Idp idp) {
        LOG.info("add IDP config");
        if (idp.getApplications() != null && idp.getApplications().size() > 0) {
            LOG.warn("IDP resource contains sub resource 'applications'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        if (idp.getTrustedIdps() != null && idp.getTrustedIdps().size() > 0) {
            LOG.warn("IDP resource contains sub resource 'trusted-idps'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        Idp createdIdp = idpDAO.addIdp(idp);
        
        UriBuilder uriBuilder = UriBuilder.fromUri(ui.getRequestUri());
        uriBuilder.path("{index}");
        URI location = uriBuilder.build(createdIdp.getRealm());
        return Response.created(location).entity(idp).build();
    }
    
    @Override
    public Response updateIdp(UriInfo ui, String realm, Idp idp) {
        if (!realm.equals(idp.getRealm().toString())) {
            throw new BadRequestException();
        }
        if (idp.getApplications() != null && idp.getApplications().size() > 0) {
            LOG.warn("IDP resource contains sub resource 'applications'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        if (idp.getTrustedIdps() != null && idp.getTrustedIdps().size() > 0) {
            LOG.warn("IDP resource contains sub resource 'trusted-idps'");
            throw new WebApplicationException(Status.BAD_REQUEST);
        }
        idpDAO.updateIdp(realm, idp);
        
        return Response.noContent().build();
    }

    @Override
    public Response deleteIdp(String realm) {
        idpDAO.deleteIdp(realm);
        
        return Response.noContent().build();
    }

    @Override
    public Response addApplicationToIdp(UriInfo ui, String realm, Application application) {
        Idp idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        if (idp.getApplications().contains(application.getRealm())) {
            LOG.warn("Application '" + application.getRealm() + "' already added");
            throw new WebApplicationException(Status.CONFLICT);
        }
        Application application2 = applicationDAO.getApplication(application.getRealm(), null);
        idpDAO.addApplicationToIdp(idp, application2);
        
        return Response.noContent().build();
    }
    
    @Override
    public Response removeApplicationFromIdp(UriInfo ui, String realm,  String applicationRealm) {
        Idp idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        
        Application foundItem = null; 
        for (Application item : idp.getApplications()) {
            if (item.getRealm().equals(applicationRealm)) {
                foundItem = item;
                break;
            }
        }
        if (foundItem == null) {
            LOG.warn("Application '" + applicationRealm + "' not found");
            throw new WebApplicationException(Status.NOT_FOUND);
        }
        idpDAO.removeApplicationFromIdp(idp, foundItem);
        
        return Response.noContent().build();
    }
    
    
    
    
    @Override
    public Response addTrustedIdpToIdp(UriInfo ui, String realm, TrustedIdp trustedIdp) {
        Idp idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        if (idp.getTrustedIdps().contains(trustedIdp.getRealm())) {
            LOG.warn("Trusted IDP '" + trustedIdp.getRealm() + "' already added");
            throw new WebApplicationException(Status.CONFLICT);
        }
        TrustedIdp trustedIpd2 = trustedIdpDAO.getTrustedIDP(trustedIdp.getRealm());
        
        idpDAO.addTrustedIdpToIdp(idp, trustedIpd2);
        
        return Response.noContent().build();
    }
    
    @Override
    public Response removeTrustedIdpFromIdp(UriInfo ui, String realm, String trustedIdpRealm) {
        Idp idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        
        TrustedIdp foundItem = null; 
        for (TrustedIdp item : idp.getTrustedIdps()) {
            if (item.getRealm().equals(trustedIdpRealm)) {
                foundItem = item;
                break;
            }
        }
        if (foundItem == null) {
            LOG.warn("Trusted IDP '" + trustedIdpRealm + "' not found");
            throw new WebApplicationException(Status.NOT_FOUND);
        }
        idpDAO.removeTrustedIdpFromIdp(idp, foundItem);
        
        return Response.noContent().build();
    }   
    
    @Override
    public Response addClaimToIdp(UriInfo ui, String realm, Claim claim) {
        Idp idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        if (idp.getClaimTypesOffered().contains(claim.getClaimType().toString())) {
            LOG.warn("Claim '" + claim.getClaimType() + "' already added");
            throw new WebApplicationException(Status.CONFLICT);
        }
        Claim claim2 = claimDAO.getClaim(claim.getClaimType().toString());
        idpDAO.addClaimToIdp(idp, claim2);
        
        return Response.noContent().build();
    }
    
    @Override
    public Response removeClaimFromIdp(UriInfo ui, String realm, String claimType) {
        Idp idp = idpDAO.getIdp(realm, Arrays.asList("all"));
        
        Claim foundItem = null; 
        for (Claim item : idp.getClaimTypesOffered()) {
            if (item.getClaimType().toString().equals(claimType)) {
                foundItem = item;
                break;
            }
        }
        if (foundItem == null) {
            LOG.warn("Claim '" + claimType + "' not found");
            throw new WebApplicationException(Status.NOT_FOUND);
        }
        idpDAO.removeClaimFromIdp(idp, foundItem);
                
        return Response.noContent().build();
    }


}