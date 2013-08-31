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
import java.util.Map;

//import javax.persistence.Column;
//import javax.persistence.Entity;
//import javax.persistence.Id;
//import javax.persistence.Table;

//@Entity
//@Table(name = "IDP")
public class IDPConfig implements Serializable {
        
    //@Id
    //private Long id;

    //@Column(name = "REALM", nullable = false, length = FIELD_LENGTH)
    //Unique
    //fed:TargetScope
    private String realm;  //wtrealm, whr

    //Unique
    //https://<host>:<port>/fediz-idp/<IDP uri>/
    private String uri;
    
    //Home Realm Discovery Service
    //Spring EL
    private String hrds;
    
    //@Column(name = "INACTIVE", nullable = true, length = FIELD_LENGTH)
    //if HRDS can't determine the home realm, should
    //the list of trusted IDPs be shown to make a choice
    private boolean provideIDPList;
    
    //If HRDS can't discover a home realm and displaying IDP list is not enabled
    //it falls back to current IDP if an authentication domain is configured
    private boolean useCurrentIDP;
    
    //Store certificate in DB or filesystem, provide options?
    //md:KeyDescriptor, use="signing"
    private String certificate;
    
    //Password to read the private key to sign metadata document
    private String certificatePassword;
    
    //fed:SecurityTokenSerivceEndpoint
    private String stsUrl;
    
    //fed:PassiveRequestorEndpoint
    //published hostname, port must be configured
    private String idpUrl;
    
    //RoleDescriptor protocolSupportEnumeration=
    // "http://docs.oasis-open.org/wsfed/federation/200706"
    // "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    // Could be more in the future
    private List<String> supportedProtocols;
    
    //list of RPs and RP-IDPs from whom we accept SignInResponse
    //which includes RP IDPs
    //key: wtrealm
    private Map<String, ServiceConfig> services;
    
    //list of trusted IDP from whom we accept SignInResponse
    //key: whr
    private Map<String, TrustedIDPConfig> trustedIDPs;
    
    //which URI to redirect for authentication
    //fediz-idp/<IDP uri>/login/auth/<auth URI>
    //wauth to auth URI mapping
    private Map<String, String> authenticationURIs;
    
    //required to create Federation Metadata document
    //fed:TokenTypesOffered
    private List<String> tokenTypesOffered;
    
    //fed:ClaimTypesOffered
    private List<String> claimTypesOffered;
    
    //ServiceDisplayName
    private String serviceDisplayName;
    
    //ServiceDescription
    private String serviceDescription;

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getHrds() {
        return hrds;
    }

    public void setHrds(String hrds) {
        this.hrds = hrds;
    }

    public boolean isProvideIDPList() {
        return provideIDPList;
    }

    public void setProvideIDPList(boolean provideIDPList) {
        this.provideIDPList = provideIDPList;
    }

    public boolean isUseCurrentIDP() {
        return useCurrentIDP;
    }

    public void setUseCurrentIDP(boolean useCurrentIDP) {
        this.useCurrentIDP = useCurrentIDP;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
    
    public String getCertificatePassword() {
        return certificatePassword;
    }

    public void setCertificatePassword(String password) {
        this.certificatePassword = password;
    }

    public String getStsUrl() {
        return stsUrl;
    }

    public void setStsUrl(String stsUrl) {
        this.stsUrl = stsUrl;
    }

    public String getIdpUrl() {
        return idpUrl;
    }

    public void setIdpUrl(String idpUrl) {
        this.idpUrl = idpUrl;
    }

    public List<String> getSupportedProtocols() {
        return supportedProtocols;
    }

    public void setSupportedProtocols(List<String> supportedProtocols) {
        this.supportedProtocols = supportedProtocols;
    }

    public Map<String, ServiceConfig> getServices() {
        return services;
    }

    public void setServices(Map<String, ServiceConfig> services) {
        this.services = services;
    }

    public Map<String, TrustedIDPConfig> getTrustedIDPs() {
        return trustedIDPs;
    }

    public void setTrustedIDPs(Map<String, TrustedIDPConfig> trustedIDPs) {
        this.trustedIDPs = trustedIDPs;
    }

    public Map<String, String> getAuthenticationURIs() {
        return authenticationURIs;
    }

    public void setAuthenticationURIs(Map<String, String> authenticationURIs) {
        this.authenticationURIs = authenticationURIs;
    }

    public List<String> getTokenTypesOffered() {
        return tokenTypesOffered;
    }

    public void setTokenTypesOffered(List<String> tokenTypesOffered) {
        this.tokenTypesOffered = tokenTypesOffered;
    }

    public List<String> getClaimTypesOffered() {
        return claimTypesOffered;
    }

    public void setClaimTypesOffered(List<String> claimTypesOffered) {
        this.claimTypesOffered = claimTypesOffered;
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

}
