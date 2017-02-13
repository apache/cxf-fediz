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

package org.apache.cxf.fediz.jetty9;

import java.util.Collections;
import java.util.List;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.processor.FedizResponse;

public class FederationUserPrincipal implements FedizPrincipal {
    private String name;
    private ClaimCollection claims;
    private FedizResponse response;
    private List<String> roles = Collections.emptyList();

    public FederationUserPrincipal(String name, FedizResponse response) {
        this.name = name;
        this.response = response;
        this.claims = new ClaimCollection(response.getClaims());
        if (response.getRoles() != null) {
            this.roles = response.getRoles();
        }
    }

    @Override
    public String getName() {
        return name;
    }


    @Override
    public ClaimCollection getClaims() {
        return claims;
    }

    // not public available
    //[TODO] maybe find better approach, custom UserIdentity
    FedizResponse getFedizResponse() {
        return response;
    }

    @Override
    public Element getLoginToken() {
        return response.getToken();
    }

    public List<String> getRoleClaims() {
        return Collections.unmodifiableList(roles);
    }
}
