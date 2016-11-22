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

package org.apache.cxf.fediz.core;

import java.util.Date;
import java.util.List;

public class TokenValidatorResponse {

    private String username;
    private String uniqueTokenId;
    private List<String> roles;
    private String issuer;
    private String audience;
    private List<Claim> claims;
    private Date expires;
    private Date created;



    public TokenValidatorResponse(String uniqueTokenId, String username, String issuer, 
                                  List<String> roles, List<Claim> claims, String audience) {
        this.username = username;
        this.issuer = issuer;
        this.roles = roles;
        this.claims = claims;
        this.audience = audience;
        this.uniqueTokenId = uniqueTokenId;
    }


    public String getUsername() {
        return username;
    }
    public String getUniqueTokenId() {
        return uniqueTokenId;
    }
    public List<String> getRoles() {
        return roles;
    }
    public String getIssuer() {
        return issuer;
    }
    public String getAudience() {
        return audience;
    }
    public List<Claim> getClaims() {
        return claims;
    }

    public Date getExpires() {
        if (expires != null) {
            return new Date(expires.getTime());
        }
        return null;
    }

    public void setExpires(Date expires) {
        if (expires != null) {
            this.expires = new Date(expires.getTime());
        } else {
            this.expires = null;
        }
    }


    public Date getCreated() {
        if (created != null) {
            return new Date(created.getTime());
        }
        return null;
    }


    public void setCreated(Date created) {
        if (created != null) {
            this.created = new Date(created.getTime());
        } else {
            this.created = null;
        }
    }


}
