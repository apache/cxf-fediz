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
package org.apache.cxf.fediz.service.oidc;

import java.util.LinkedList;
import java.util.List;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;

public class ClientAccessTokens {
    private Client client;
    private List<ServerAccessToken> accessTokens = new LinkedList<ServerAccessToken>();
    public ClientAccessTokens(Client c, List<ServerAccessToken> accessTokens) {
        this.client = c;
        this.accessTokens = accessTokens;
    }
    public Client getClient() {
        return client;
    }
    public void setClient(Client client) {
        this.client = client;
    }
    public List<ServerAccessToken> getAccessTokens() {
        return accessTokens;
    }
    public void setAccessTokens(List<ServerAccessToken> accessTokens) {
        this.accessTokens = accessTokens;
    }
    

}
