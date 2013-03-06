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

package org.apache.cxf.fediz.tomcat;

import java.util.List;

import org.w3c.dom.Element;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FederationPrincipal;

public class FederationPrincipalImpl extends GenericPrincipal implements FederationPrincipal {

    protected ClaimCollection claims;
    protected Element loginToken;

    public FederationPrincipalImpl(String username, List<String> roles,
            List<Claim> claims, Element loginToken) {
        super(username, null, roles);
        this.claims = new ClaimCollection(claims);
        this.loginToken = loginToken;
    }

    public ClaimCollection getClaims() {
        return this.claims;
    }

    @Override
    public Element getLoginToken() {
        return loginToken;
    }

}
