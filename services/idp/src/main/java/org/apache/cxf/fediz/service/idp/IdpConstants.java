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

public final class IdpConstants {

    public static final String IDP_CONFIG = "idpConfig";
    
    /**
     * A key used to store context/state when communicating with a trusted third party IdP.
     */
    public static final String TRUSTED_IDP_CONTEXT = "trusted_idp_context";
    
    /**
     * A key used to store a parsed SAMLRequest as an OpenSAML AuthnRequest Object
     */
    public static final String SAML_AUTHN_REQUEST = "saml_authn_request";
    
    /**
     * A key used to store the home realm for the given request.
     */
    public static final String HOME_REALM = "home_realm";
    
    private IdpConstants() {
        // complete
    }
}
