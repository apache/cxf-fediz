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
package org.apache.cxf.fediz.service.idp.model;

import java.io.Serializable;
import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;

//import javax.persistence.Column;
//import javax.persistence.Entity;
//import javax.persistence.Id;
//import javax.persistence.Table;

//@Entity
//@Table(name = "SERVICE")
@XmlRootElement(name = "Service", namespace = "http://org.apache.cxf.fediz")
public class ServiceConfig implements Serializable {

        
    //@Id
    //private Long id;

            
    //Could be imported from Metadata document or manually filled
    
    //@Column(name = "REALM", nullable = true, length = FIELD_LENGTH)
    private String realm;  //wtrealm, whr

    //Could be read from Metadata, RoleDescriptor protocolSupportEnumeration=
    // "http://docs.oasis-open.org/wsfed/federation/200706"
    // Metadata could provide more than one but one must be chosen
    private String protocol;
 
    // Public key only
    // Could be read from Metadata, md:KeyDescriptor, use="encryption"
    private String encryptionCertificate;
    
    // Could be read from Metadata, fed:ClaimTypesRequested
    private List<RequestClaim> requestedClaims;
    
    //Could be read from Metadata, ServiceDisplayName
    //usage for list of application where user is logged in
    private String serviceDisplayName;
    
    //Could be read from Metadata, ServiceDescription
    //usage for list of application where user is logged in
    private String serviceDescription;
    
    //Could be read from Metadata, RoleDescriptor
    //fed:ApplicationServiceType, fed:SecurityTokenServiceType
    private String role;
    
    
    // Not in Metadata, configured in IDP or passed in wreq parameter
    private String tokenType;
    
    // Not in Metadata, configured in IDP or passed in wreq parameter
    private String lifeTime;

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getEncryptionCertificate() {
        return encryptionCertificate;
    }

    public void setEncryptionCertificate(String encryptionCertificate) {
        this.encryptionCertificate = encryptionCertificate;
    }

    public List<RequestClaim> getRequestedClaims() {
        return requestedClaims;
    }

    public void setRequestedClaims(List<RequestClaim> requestedClaims) {
        this.requestedClaims = requestedClaims;
    }

    public String getServiceDisplayName() {
        return serviceDisplayName;
    }

    public void setServiceDisplayName(String serviceDisplayName) {
        this.serviceDisplayName = serviceDisplayName;
    }

    public String getServiceDescription() {
        return serviceDescription;
    }

    public void setServiceDescription(String serviceDescription) {
        this.serviceDescription = serviceDescription;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getLifeTime() {
        return lifeTime;
    }

    public void setLifeTime(String lifeTime) {
        this.lifeTime = lifeTime;
    }
        

}
