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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.model.IDPConfig;
import org.apache.cxf.fediz.service.idp.model.ServiceConfig;

public class ConfigServiceSpring implements ConfigService {

    private Map<String, Application> serviceConfigs = new HashMap<String, Application>();
    private Map<String, Idp> idpConfigs = new HashMap<String, Idp>();


    @Override
    public Idp getIDP(String realm) {
        if (realm == null || realm.length() == 0) {
            return this.getIdpConfigs().get(0);
        } else {
            return idpConfigs.get(realm);
        }
    }

    @Override
    public void setIDP(Idp config) {
        idpConfigs.put(config.getRealm(), config);
    }

    @Override
    public void removeIDP(String realm) {
        idpConfigs.remove(realm);
    }

    public List<Application> getServiceConfigs() {
        return new ArrayList<Application>(serviceConfigs.values());
    }

    public void setServiceConfigs(List<ServiceConfig> serviceList) {
        for (ServiceConfig s : serviceList) {
            serviceConfigs.put(s.getRealm(), s);
        }
    }
    
    public List<Idp> getIdpConfigs() {
        return new ArrayList<Idp>(idpConfigs.values());
    }

    public void setIdpConfigs(List<IDPConfig> idpList) {
        for (IDPConfig i : idpList) {
            idpConfigs.put(i.getRealm(), i);
        }
    }

}
