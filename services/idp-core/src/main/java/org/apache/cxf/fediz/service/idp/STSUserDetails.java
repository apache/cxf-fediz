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
package org.apache.cxf.fediz.service.idp;

import java.util.Collection;

import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class STSUserDetails extends User {

    private static final long serialVersionUID = 1975259365978165675L;

    private SecurityToken token;

    public STSUserDetails(String username, String password, boolean enabled, boolean accountNonExpired,
                          boolean credentialsNonExpired, boolean accountNonLocked,
                          Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    public STSUserDetails(String username, String password,
                          Collection<? extends GrantedAuthority> authorities, SecurityToken token) {
        super(username, password, true, true, true, true, authorities);
        this.token = token;
    }

    public SecurityToken getSecurityToken() {
        return this.token;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof STSUserDetails)) {
            return false;
        }

        if (token != null && !token.equals(((STSUserDetails)object).token)) {
            return false;
        } else  if (token == null && ((STSUserDetails)object).token != null) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int hashCode = 17;
        if (token != null) {
            hashCode *= 31 * token.hashCode();
        }

        return hashCode * super.hashCode();
    }
}
