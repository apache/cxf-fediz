/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//[TODO] Should it be a Subject instead of Principal (tomcat uses a prinicpal in GenericPrinicpial)

package org.apache.cxf.fediz.core;

import java.security.Principal;

public interface FederationPrincipal extends Principal {

    public ClaimCollection getClaims();

}

/*
public class FederationPrincipal implements Principal {

    protected String username = null;
    protected List<String> roles = null;
    protected ClaimCollection claims = null;

    public FederationPrincipal(String username) {
        this(username, null, null);
    }

    public FederationPrincipal(String username, List<String> roles) {
        this(username, roles, null);
    }

    public FederationPrincipal(String username, List<String> roles,
            ClaimCollection claims) {
        this.username = username;
        this.roles = roles;
        this.claims = claims;
    }

    @Override
    public String getName() {
        return this.username;
    }

    public List<String> getRoles() {
        return Collections.unmodifiableList(this.roles);
    }

    public ClaimCollection getClaims() {
        return this.claims;
    }

}*/
