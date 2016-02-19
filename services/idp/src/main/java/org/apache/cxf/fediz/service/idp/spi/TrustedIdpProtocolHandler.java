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
package org.apache.cxf.fediz.service.idp.spi;

import java.net.URL;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.springframework.webflow.execution.RequestContext;

public interface TrustedIdpProtocolHandler extends ProtocolHandler {
    
    boolean canHandleRequest(HttpServletRequest request);

    // Only supports HTTP GET SignIn Requests
    URL mapSignInRequest(RequestContext context, Idp idp, TrustedIdp trustedIdp);
    
    // Allow for processing of the Response + redirect again (required by some protocols)
    URL processSignInResponse(RequestContext context, Idp idp, TrustedIdp trustedIdp);
    
    //Hook in <action-state id="validateToken"> of federation-signin-response.xml
    SecurityToken mapSignInResponse(RequestContext context, Idp idp, TrustedIdp trustedIdp);

}
