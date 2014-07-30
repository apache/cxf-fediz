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

import java.net.URI;

public class FedizConstants {
   
    public static final URI DEFAULT_ROLE_URI = URI
        .create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role");

    public static final String WS_TRUST_13_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    
    public static final String WS_TRUST_2005_02_NS = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    
    public static final String SAML2_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
    
    public static final String WS_FEDERATION_NS = "http://docs.oasis-open.org/wsfed/federation/200706";
    
    public static final String WS_ADDRESSING_NS = "http://www.w3.org/2005/08/addressing";
    
    public static final String SCHEMA_INSTANCE_NS = "http://www.w3.org/2001/XMLSchema-instance";
    
    protected FedizConstants() {
        
    }
}
