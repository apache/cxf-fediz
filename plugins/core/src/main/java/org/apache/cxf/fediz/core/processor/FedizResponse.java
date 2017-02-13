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

package org.apache.cxf.fediz.core.processor;

import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;

public class FedizResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    private String audience;
    private String username;
    private List<String> roles;
    private String issuer;
    private List<Claim> claims;
    private transient Element token;
    private String uniqueTokenId;

    /**
     * Created time
     */
    private Date tokenCreated;

    /**
     * Expiration time
     */
    private Date tokenExpires;

    //CHECKSTYLE:OFF
    public FedizResponse(String username, String issuer, List<String> roles, List<Claim> claims, String audience,
        Date created, Date expires, Element token, String uniqueTokenId) {
        this.username = username;
        this.issuer = issuer;
        this.roles = roles;
        this.claims = claims;
        this.audience = audience;
        if (created != null) {
            this.tokenCreated = new Date(created.getTime());
        }
        if (expires != null) {
            this.tokenExpires = new Date(expires.getTime());
        }
        this.token = token;
        this.uniqueTokenId = uniqueTokenId;
    }

    public String getUniqueTokenId() {
        return uniqueTokenId;
    }

    public String getAudience() {
        return audience;
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        if (roles == null) {
            return null;
        }
        return Collections.unmodifiableList(roles);
    }

    public String getIssuer() {
        return issuer;
    }

    public List<Claim> getClaims() {
        if (claims == null) {
            return null;
        }
        return Collections.unmodifiableList(claims);
    }

    public Date getTokenCreated() {
        if (tokenCreated != null) {
            return new Date(tokenCreated.getTime());
        }
        return null;
    }

    public Date getTokenExpires() {
        if (tokenExpires != null) {
            return new Date(tokenExpires.getTime());
        }
        return null;
    }

    public Element getToken() {
        return token;
    }


}
