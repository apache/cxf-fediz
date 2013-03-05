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

import java.io.Serializable;
import java.util.Collection;

import org.apache.cxf.fediz.core.FederationResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Represents a successful WS-Federation based authentication.
 */
public class FederationAuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object credentials;
    private final Object principal;
    private final UserDetails userDetails;
    private final FederationResponse response;

    
    public FederationAuthenticationToken(final Object principal, final Object credentials,
        final Collection<? extends GrantedAuthority> authorities, final UserDetails userDetails,
        final FederationResponse response) {
        super(authorities);

        if ((principal == null) || "".equals(principal) || (credentials == null)
            || "".equals(credentials) || (authorities == null) || (userDetails == null) || (response == null)) {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }

        this.principal = principal;
        this.credentials = credentials;
        this.userDetails = userDetails;
        this.response = response;
        setAuthenticated(true);
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public FederationResponse getResponse() {
        return this.response;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(" Response: ").append(this.response);
        sb.append(" Credentials: ").append(this.credentials);

        return sb.toString();
    }

}
