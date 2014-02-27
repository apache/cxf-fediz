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
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.service.EntitlementDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class EntitlementServiceImpl implements EntitlementService {

    private static final Logger LOG = LoggerFactory
            .getLogger(EntitlementServiceImpl.class);

    @Autowired
    private EntitlementDAO entitlementDAO;

    @Override
    public Entitlements getEntitlements(int start, int size, UriInfo uriInfo) {
        List<Entitlement> entitlements = entitlementDAO.getEntitlements(start, size);
        
        Entitlements list = new Entitlements();
        list.setEntitlements(entitlements);
        
        return list;
    }
    
    @Override
    public Response addEntitlement(UriInfo ui, Entitlement entitlement) {
        Entitlement createdEntitlement = entitlementDAO.addEntitlement(entitlement);
        
        UriBuilder uriBuilder = UriBuilder.fromUri(ui.getRequestUri());
        uriBuilder.path("{index}");
        URI location = uriBuilder.build(createdEntitlement.getName());
        
        LOG.debug("Entitlement '" + createdEntitlement.getName() + "' added");
        return Response.created(location).entity(entitlement).build();
    }
    
    @Override
    public Entitlement getEntitlement(String name) {
        Entitlement entitlement = entitlementDAO.getEntitlement(name);
        if (entitlement == null) {
            throw new NotFoundException();
        } else {
            return entitlement;
        }
    }

    @Override
    public Response updateEntitlement(UriInfo ui, String name, Entitlement entitlement) {
        if (!name.equals(entitlement.getName())) {
            throw new BadRequestException();
        }
        entitlementDAO.updateEntitlement(name, entitlement);
        
        LOG.debug("Entitlement '" + entitlement.getName() + "' updated");
        return Response.noContent().build();
    }

    @Override
    public Response deleteEntitlement(String name) {
        entitlementDAO.deleteEntitlement(name);
        
        LOG.debug("Entitlement '" + name + "' deleted");
        return Response.noContent().build();
    }

}