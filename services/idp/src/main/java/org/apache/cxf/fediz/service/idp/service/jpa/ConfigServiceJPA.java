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
import java.util.HashSet;
import java.util.Set;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.rest.IdpService;
import org.apache.cxf.fediz.service.idp.service.ConfigService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;


public class ConfigServiceJPA implements ConfigService {

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpDAOJPAImpl.class);
    
    IdpService idpService;

    @Override
    public Idp getIDP(String realm) {
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        try {
            final Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
            authorities.add(new SimpleGrantedAuthority("IDP_LIST"));
            
            UsernamePasswordAuthenticationToken technicalUser =
                new UsernamePasswordAuthenticationToken("IDP_TEST", "N.A", authorities);
            
            SecurityContextHolder.getContext().setAuthentication(technicalUser);
            
            if (realm == null || realm.length() == 0) {
                return idpService.getIdps(0, 1, Arrays.asList("all"), null).getIdps().iterator().next();
            } else {
                return idpService.getIdp(realm, Arrays.asList("all"));
            }
        } finally {
            SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
            LOG.error("Old Spring security context restored");
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
