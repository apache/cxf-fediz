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

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import org.apache.cxf.fediz.service.idp.model.IDPConfig;
import org.apache.cxf.fediz.service.idp.service.ConfigService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/idp")
@Produces("text/xml")
public class IDPServices {
    
    private static final Logger LOG = LoggerFactory.getLogger(IDPServices.class);

    private ConfigService configService;
    
    public IDPServices() {
    }
    
    
    @GET
    @Path("/{id}/")
    public IDPConfig getIDP(@PathParam("id") String id) {
        LOG.info("get IDP config: " + id);
        
        return configService.getIDPConfig(id);
    }

    @PUT
    @Path("/idp/")
    public Response updateIDP(IDPConfig idp) {
        LOG.info("update IDP config: " + idp.getRealm());
        
        IDPConfig idpConfig = configService.getIDPConfig(idp.getRealm());
        Response r;
        if (idpConfig != null) {
            //configService.put(idp.getRealm(), idp);
            r = Response.ok().build();
        } else {
            r = Response.notModified().build();
        }

        return r;
    }

    @POST
    @Path("/")
    public Response addIDP(IDPConfig idp) {
        LOG.info("add IDP config: " + idp.getRealm());
        
        //configService.put(idp.getRealm(), idp);

        return Response.ok(idp).build();
    }

    @DELETE
    @Path("/{id}/")
    public Response deleteIDP(@PathParam("id") String id) {
        LOG.info("delete IDP config: " + id);
        
        IDPConfig config = configService.getIDPConfig(id);
        
        Response r;
        if (config != null) {
            r = Response.ok().build();
            //configService.remove(config);
        } else {
            r = Response.notModified().build();
        }

        return r;
    }

    
    public ConfigService getConfigService() {
        return configService;
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

}