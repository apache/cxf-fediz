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
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.service.TrustedIdpDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class TrustedIdpServiceImpl implements TrustedIdpService {

    private static final Logger LOG = LoggerFactory
            .getLogger(TrustedIdpServiceImpl.class);

    @Autowired
    private TrustedIdpDAO trustedIdpDAO;

    
    
    @Override
    public Response updateTrustedIDP(UriInfo ui, String realm, TrustedIdp trustedIdp) {
        if (!realm.equals(trustedIdp.getRealm().toString())) {
            throw new BadRequestException();
        }
        trustedIdpDAO.updateTrustedIDP(realm, trustedIdp);
        
        return Response.noContent().build();
    }
    
    @Override
    public TrustedIdps getTrustedIDPs(int start, int size, UriInfo uriInfo) {
        List<TrustedIdp> trustedIdps = trustedIdpDAO.getTrustedIDPs(start, size);
        
        TrustedIdps list = new TrustedIdps();
        list.setTrustedIDPs(trustedIdps);
        return list;
    }
    
    @Override
    public TrustedIdp getTrustedIDP(String realm) {
        return this.trustedIdpDAO.getTrustedIDP(realm);
    }
    
    @Override
    public Response addTrustedIDP(UriInfo ui, TrustedIdp trustedIDP) {
        LOG.info("add Trusted IDP config");
        
        TrustedIdp createdTrustedIdp = trustedIdpDAO.addTrustedIDP(trustedIDP);
        
        UriBuilder uriBuilder = UriBuilder.fromUri(ui.getRequestUri());
        uriBuilder.path("{index}");
        URI location = uriBuilder.build(createdTrustedIdp.getRealm());
        return Response.created(location).entity(trustedIDP).build();
    }

    @Override
    public Response deleteTrustedIDP(String realm) {
        trustedIdpDAO.deleteTrustedIDP(realm);
        
        return Response.noContent().build();
    }
           
    


}