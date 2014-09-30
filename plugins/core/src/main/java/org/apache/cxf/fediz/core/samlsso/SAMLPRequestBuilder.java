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

package org.apache.cxf.fediz.core.samlsso;

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;

/**
 * This interface defines a methods to create a SAML 2.0 Protocol AuthnRequest and LogoutRequest.
 */
public interface SAMLPRequestBuilder {
    
    /**
     * Create a SAML 2.0 Protocol AuthnRequest
     */
    AuthnRequest createAuthnRequest(
        String issuerId,
        String assertionConsumerServiceAddress
    ) throws Exception;
    
    /**
     * Create a SAML 2.0 Protocol LogoutRequest
     */
    LogoutRequest createLogoutRequest(
        String issuerId,
        String reason,
        SamlAssertionWrapper authenticatedAssertion
    ) throws Exception;
}
