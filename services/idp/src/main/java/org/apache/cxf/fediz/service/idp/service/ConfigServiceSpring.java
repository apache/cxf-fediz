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
package org.apache.cxf.fediz.service.idp.service;

import java.util.List;

import org.apache.cxf.fediz.service.idp.model.IDPConfig;
import org.apache.cxf.fediz.service.idp.model.ServiceConfig;

public class ConfigServiceSpring implements ConfigService {

    private List<ServiceConfig> serviceConfigs;
    private List<IDPConfig> idpConfigs;

    
    
    @Override
    public ServiceConfig getServiceConfig(String realm) {
        for (ServiceConfig cfg : serviceConfigs) {
            if (realm.equals(cfg.getRealm())) {
                return cfg;
            }
        }
        return null;
    }

    @Override
    public IDPConfig getIDPConfig(String realm) {
        for (IDPConfig cfg : idpConfigs) {
            if (realm.equals(cfg.getRealm())) {
                return cfg;
            }
        }
        return null;
    }
    
    public List<ServiceConfig> getServiceConfigs() {
        return serviceConfigs;
    }

    public void setServiceConfigs(List<ServiceConfig> serviceConfigs) {
        this.serviceConfigs = serviceConfigs;
    }

    public List<IDPConfig> getIdpConfigs() {
        return idpConfigs;
    }

    public void setIdpConfigs(List<IDPConfig> idpConfigs) {
        this.idpConfigs = idpConfigs;
    }

}
