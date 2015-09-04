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

import org.w3c.dom.Element;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AbstractAuthenticationToken;
import org.springframework.security.userdetails.UserDetails;

/**
 * Represents a successful WS-Federation based authentication.
 */
public class FederationAuthenticationToken extends AbstractAuthenticationToken
    implements Serializable, FedizPrincipal {

    private static final long serialVersionUID = 1L;

    private final Object credentials;
    private final Object principal;
    private final UserDetails userDetails;
    private final FedizResponse response;

    
    public FederationAuthenticationToken(final Object principal, final Object credentials,
        final GrantedAuthority[] authorities, final UserDetails userDetails,
        final FedizResponse response) {
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

    public FedizResponse getResponse() {
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

    @Override
    public ClaimCollection getClaims() {
        return new ClaimCollection(response.getClaims());
    }

    @Override
    public Element getLoginToken() {
        return response.getToken();
    }

}
