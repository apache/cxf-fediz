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

import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.springframework.security.Authentication;
import org.springframework.security.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UsernameNotFoundException;

/**
 * Abstract class to construct a new User object based on the provided FederationResponseAuthenticationToken.
 */
public abstract class AbstractFederationUserDetailsService
        implements AuthenticationUserDetailsService {

    /*
    public final UserDetails loadUserDetails(final Authentication token) {

    }*/
    @Override
    public final UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException {
        if (!(token instanceof FederationResponseAuthenticationToken)) {
            return null;
        }
        FederationResponseAuthenticationToken fedToken = (FederationResponseAuthenticationToken)token;
        return loadUserDetails(fedToken.getResponse());
    }

    /**
     * Protected template method for construct a {@link org.springframework.security.core.userdetails.UserDetails}
     * via the supplied FedizResponse
     *
     * @return the newly created UserDetails object.
     */
    protected abstract UserDetails loadUserDetails(FedizResponse response);


}
