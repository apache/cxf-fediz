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

import java.util.Map;

import javax.xml.bind.annotation.XmlRootElement;

import org.apache.cxf.fediz.service.idp.model.ServiceConfig;

@XmlRootElement
public class IDPServiceConfigs {

    private Map<String, ServiceConfig> services;

    public IDPServiceConfigs() {
    }

    public IDPServiceConfigs(Map<String, ServiceConfig> services) {
        this.services = services;
    }

    public Map<String, ServiceConfig> getServices() {
        return services;
    }

    public void setServices(Map<String, ServiceConfig> services) {
        this.services = services;
    }

//    @GET
//    @Path("{wtrealm}")
//    public ServiceConfig getServiceConfig(@PathParam("wtrealm") String wtrealm) {
//        ServiceConfig config = services.get(wtrealm);
//        if (config == null) {
//            throw new NotFoundException();
//        }
//        return config;
//    }

//    @GET
//    public IDPServiceConfigs getState() {
//        return this;
//    }
}