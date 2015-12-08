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

import org.apache.cxf.rs.security.oauth2.common.Client;

/**
 * Extends the OAuth Client by associating a client with a particular realm.
 */
public class FedizClient extends Client {
    
    private static final long serialVersionUID = -6186868745413555170L;
    private String homeRealm;
    
    public FedizClient() {
        super();
    }
    
    public FedizClient(String clientId, String clientSecret, boolean isConfidential) {
        super(clientId, clientSecret, isConfidential);
    }

    public FedizClient(String clientId, 
                  String clientSecret,
                  boolean isConfidential,
                  String applicationName) {
        super(clientId, clientSecret, isConfidential, applicationName);
        
    }

    public String getHomeRealm() {
        return homeRealm;
    }

    public void setHomeRealm(String homeRealm) {
        this.homeRealm = homeRealm;
    }
    
}

