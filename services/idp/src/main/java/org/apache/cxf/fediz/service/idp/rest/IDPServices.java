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

import javax.ws.rs.BadRequestException;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import org.apache.cxf.fediz.service.idp.model.IDPConfig;
import org.apache.cxf.fediz.service.idp.model.ServiceConfig;
import org.apache.cxf.fediz.service.idp.model.TrustedIDPConfig;
import org.apache.cxf.fediz.service.idp.service.ConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/idp")
@Produces({ "text/xml", "application/xml", "application/json", "text/html" })
public class IDPServices {

    private static final Logger LOG = LoggerFactory
            .getLogger(IDPServices.class);

    private ConfigService configService;

    public IDPServices() {
    }

    @GET
    @Path("/{realm}/")
    public IDPConfig getIDP(@PathParam("realm") String realm) {
        LOG.info("get IDP config for realm: " + realm);

        IDPConfig currentConfig = configService.getIDPConfig(realm);
        if (currentConfig == null) {
            throw new NotFoundException();
        }
        return currentConfig;
    }

    @PUT
    @Path("/")
    public Response updateIDP(IDPConfig idp) {
        LOG.info("update IDP config for realm: " + idp.getRealm());

        IDPConfig currentConfig = getIDP(idp.getRealm());

        Response r;
        if (!currentConfig.equals(idp)) {
            configService.setIDPConfig(idp);
            r = Response.ok().build();
        } else {
            r = Response.notModified().build();
        }
        return r;
    }

    @POST
    @Path("/")
    public Response addIDP(IDPConfig idp) {
        LOG.info("add IDP config for realm: " + idp.getRealm());

        if (configService.getIDPConfig(idp.getRealm()) != null) {
            LOG.info("IDP config with realm: " + idp.getRealm()
                    + " already exists");
            throw new BadRequestException();
        }
        configService.setIDPConfig(idp);
        return Response.ok(idp).build();
    }

    @DELETE
    @Path("/{realm}/")
    public Response deleteIDP(@PathParam("realm") String realm) {
        LOG.info("delete IDP config for realm: " + realm);

        IDPConfig config = configService.removeIDPConfig(realm);

        Response r;
        if (config != null) {
            r = Response.ok().build();
        } else {
            r = Response.notModified().build();
        }

        return r;
    }

    @GET
    @Path("{realm}/services")
    public IDPServiceConfigs getServices(@PathParam("realm") String realm) {
        return new IDPServiceConfigs(getIDP(realm).getServices());
    }
    
    @GET
    @Path("{realm}/services/{wtrealm}")
    public ServiceConfig getServiceConfig(@PathParam("realm") String realm, 
                                          @PathParam("wtrealm") String wtrealm) {
        return getIDP(realm).getServices().get(wtrealm);
    }

//    @Path("{realm}/services")
//    public IDPServiceConfigs getServicesSubresource(@PathParam("realm") String realm) {
//        return new IDPServiceConfigs(getIDP(realm).getServices());
//    }
    
    @GET
    @Path("{realm}/trusted-idps")
    public IDPTrustedIdps getTrustedIdps(@PathParam("realm") String realm) {
        return new IDPTrustedIdps(getIDP(realm).getTrustedIDPs());
    }
    
    @GET
    @Path("{realm}/trusted-idps/{whr}")
    public TrustedIDPConfig getTrustedIdpConfig(@PathParam("realm") String realm,
                                                @PathParam("whr") String whr) {
        return getIDP(realm).getTrustedIDPs().get(whr);
    }

//    @Path("{realm}/trusted-idps")
//    public IDPTrustedIdps getTrustedIdpsSubresource(@PathParam("realm") String realm) {
//        return new IDPTrustedIdps(getIDP(realm).getTrustedIDPs());
//    }
    
    public ConfigService getConfigService() {
        return configService;
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

}