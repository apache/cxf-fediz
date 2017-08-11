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
package org.apache.cxf.fediz.service.oidc.clients;

import java.util.LinkedList;
import java.util.List;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;

public class ClientCodeGrants {
    private Client client;
    private List<ServerAuthorizationCodeGrant> codeGrants = new LinkedList<ServerAuthorizationCodeGrant>();
    public ClientCodeGrants(Client c, List<ServerAuthorizationCodeGrant> codeGrants) {
        this.client = c;
        this.codeGrants = codeGrants;
    }
    public Client getClient() {
        return client;
    }
    public void setClient(Client client) {
        this.client = client;
    }
    public List<ServerAuthorizationCodeGrant> getCodeGrants() {
        return codeGrants;
    }
    public void setCodeGrants(List<ServerAuthorizationCodeGrant> codeGrants) {
        this.codeGrants = codeGrants;
    }


}
