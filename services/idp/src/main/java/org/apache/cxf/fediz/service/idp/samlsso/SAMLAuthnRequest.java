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

package org.apache.cxf.fediz.service.idp.samlsso;

import java.io.Serializable;

import org.opensaml.saml.saml2.core.AuthnRequest;

/**
 * This class encapsulates a (parsed) SAML AuthnRequest Object. The OpenSAML AuthnRequest Object is not
 * serializable.
 */
public class SAMLAuthnRequest implements Serializable {
    /**
     * 
     */
    private static final long serialVersionUID = 4353024755428346545L;
    
    private String issuer;
    private String consumerServiceURL;
    private String requestId;
    private boolean forceAuthn;
    private String subjectNameId;
    
    public SAMLAuthnRequest(AuthnRequest authnRequest) {
        if (authnRequest.getIssuer() != null) {
            issuer = authnRequest.getIssuer().getValue();
        }
        
        consumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
        requestId = authnRequest.getID();
        forceAuthn = authnRequest.isForceAuthn().booleanValue();
        if (authnRequest.getSubject() != null && authnRequest.getSubject().getNameID() != null) {
            subjectNameId = authnRequest.getSubject().getNameID().getValue();
        }
    }
    
    public String getIssuer() {
        return issuer;
    }
    
    public String getConsumerServiceURL() {
        return consumerServiceURL;
    }
    
    public String getRequestId() {
        return requestId;
    }
    
    public boolean isForceAuthn() {
        return forceAuthn;
    }
    
    public String getSubjectNameId() {
        return subjectNameId;
    }
}
