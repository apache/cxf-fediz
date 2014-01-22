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

package org.apache.cxf.fediz.service.idp.service.jpa;

import java.util.Arrays;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.rest.IdpService;
import org.apache.cxf.fediz.service.idp.service.ConfigService;


public class ConfigServiceJPA implements ConfigService {

    IdpService idpService;

    @Override
    public Idp getIDP(String realm) {
        if (realm == null || realm.length() == 0) {
            return idpService.getIdps(0, 1, Arrays.asList("all"), null).getIdps().iterator().next();
        } else {
            return idpService.getIdp(realm, Arrays.asList("all"));
        }
    }

    @Override
    public void setIDP(Idp config) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void removeIDP(String realm) {
        // TODO Auto-generated method stub
        
    }

    public IdpService getIdpService() {
        return idpService;
    }

    public void setIdpService(IdpService idpService) {
        this.idpService = idpService;
    }
    

}
