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


public final class SAMLSSOTestUtils {
    
 
    public static final String SAMPLE_EMPTY_SAML_RESPONSE = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<saml2p:Response ID=\"c4b78949-d52e-4ae0-ad44-04ef58fe1ca8\" "
        + "InResponseTo=\"612223b6-fb12-4c40-9a31-9bd94e09a579\" "
        + "IssueInstant=\"2014-07-22T15:32:52.933Z\" Version=\"2.0\" "
        + "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
        + "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
        + "http://localhost:12345/idp/samlsso</saml2:Issuer><saml2p:Status>"
        + "<saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
        + "</saml2p:Status></saml2p:Response>";
    
    private SAMLSSOTestUtils() {
        
    }
    
}
