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
package org.apache.cxf.fediz.spring.authentication;

import java.util.*;

import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FederationResponse;
import org.apache.cxf.fediz.spring.FederationUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * This AuthenticationUserDetailsService implementation creates a FederationUser
 * object based on the data in the provided FederationResponseAuthenticationToken.
 */
public class GrantedAuthoritiesUserDetailsFederationService
        extends AbstractFederationUserDetailsService {

    @Override
    protected UserDetails loadUserDetails(FederationResponse response) {
        
        final List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
        
        for (final String role : response.getRoles()) {
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
        }
        return new FederationUser(response.getUsername(), "N/A",
                        grantedAuthorities, new ClaimCollection(response.getClaims()));
        
    }
}
