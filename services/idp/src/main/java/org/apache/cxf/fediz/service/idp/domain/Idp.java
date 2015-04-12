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
package org.apache.cxf.fediz.service.idp.domain;

import java.io.Serializable;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "idp", namespace = "http://org.apache.cxf.fediz/")
@XmlType(propOrder = {"realm", "uri", "serviceDisplayName", "serviceDescription", "idpUrl", "stsUrl",
                     "certificate", "certificatePassword", "provideIdpList", "useCurrentIdp", "hrds",
                     "rpSingleSignOutConfirmation", "supportedProtocols", "tokenTypesOffered", "claimTypesOffered",
                     "authenticationURIs", "applications", "trustedIdps", "id", "rpSingleSignOutCleanupConfirmation" })
public class Idp implements Serializable {

    private static final long serialVersionUID = -5570301342547139039L;

    
    protected int id;
    
    // Unique
    // fed:TargetScope
    protected String realm; // wtrealm, whr

    // Unique
    // https://<host>:<port>/fediz-idp/<IDP uri>/
    protected String uri;

    // Home Realm Discovery Service
    // Spring EL
    protected String hrds;

    // @Column(name = "INACTIVE", nullable = true, length = FIELD_LENGTH)
    // if HRDS can't determine the home realm, should
    // the list of trusted IDPs be shown to make a choice
    protected boolean provideIdpList;

    // If HRDS can't discover a home realm and displaying IDP list is not
    // enabled
    // it falls back to current IDP if an authentication domain is configured
    protected boolean useCurrentIdp;

    // Store certificate in DB or filesystem, provide options?
    // md:KeyDescriptor, use="signing"
    protected String certificate;

    // Password to read the private key to sign metadata document
    protected String certificatePassword;

    // fed:SecurityTokenSerivceEndpoint
    protected URL stsUrl;

    // fed:PassiveRequestorEndpoint
    // published hostname, port must be configured
    protected URL idpUrl;

    // RoleDescriptor protocolSupportEnumeration=
    // "http://docs.oasis-open.org/wsfed/federation/200706"
    // "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    // Could be more in the future
    protected List<String> supportedProtocols = new ArrayList<String>();

    // list of RPs and RP-IDPs from whom we accept SignInResponse
    // which includes RP IDPs
    // key: wtrealm
    protected List<Application> applications = new ArrayList<Application>();

    // list of trusted IDP from whom we accept SignInResponse
    // key: whr
    protected List<TrustedIdp> trustedIdpList = new ArrayList<TrustedIdp>();

    // which URI to redirect for authentication
    // fediz-idp/<IDP uri>/login/auth/<auth URI>
    // wauth to auth URI mapping
    protected Map<String, String> authenticationURIs = new HashMap<String, String>();

    // required to create Federation Metadata document
    // fed:TokenTypesOffered
    protected List<String> tokenTypesOffered = new ArrayList<String>();

    // fed:ClaimTypesOffered
    protected List<Claim> claimTypesOffered = new ArrayList<Claim>();

    // ServiceDisplayName
    protected String serviceDisplayName;

    // ServiceDescription
    protected String serviceDescription;
    
    // The user/browser must explicitly confirm to logout from all applications
    private boolean rpSingleSignOutConfirmation;
    
    // Is explicit confirmation required when the "cleanup" URL is called
    private boolean rpSingleSignOutCleanupConfirmation;
    
    @XmlAttribute
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }
    
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

    public boolean isProvideIdpList() {
        return provideIdpList;
    }

    public void setProvideIdpList(boolean provideIdpList) {
        this.provideIdpList = provideIdpList;
    }

    public boolean isUseCurrentIdp() {
        return useCurrentIdp;
    }

    public void setUseCurrentIdp(boolean useCurrentIdp) {
        this.useCurrentIdp = useCurrentIdp;
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

    public URL getStsUrl() {
        return stsUrl;
    }

    public void setStsUrl(URL stsUrl) {
        this.stsUrl = stsUrl;
    }

    public URL getIdpUrl() {
        return idpUrl;
    }

    public void setIdpUrl(URL idpUrl) {
        this.idpUrl = idpUrl;
    }

    @XmlElementWrapper(name = "supportedProtocols")
    public List<String> getSupportedProtocols() {
        return supportedProtocols;
    }

    public void setSupportedProtocols(List<String> supportedProtocols) {
        this.supportedProtocols = supportedProtocols;
    }

    public Application findApplication(String realmApplication) {
        for (Application item : applications) {
            if (realmApplication.equals(item.getRealm())) {
                return item;
            }
        }
        return null;
    }
    
    @XmlElementWrapper(name = "applications")
    @XmlElementRef(name = "application")
    public List<Application> getApplications() {
        return applications;
    }

    public void setApplications(List<Application> applications) {
        this.applications = applications;
    }

    public TrustedIdp findTrustedIdp(String realmTrustedIdp) {
        for (TrustedIdp item : trustedIdpList) {
            if (realmTrustedIdp.equals(item.getRealm())) {
                return item;
            }
        }
        return null;
    }
    
    @XmlElementWrapper(name = "trustedIdps")
    @XmlElementRef(name = "trustedIdp")
    public List<TrustedIdp> getTrustedIdps() {
        return trustedIdpList;
    }

    public Map<String, String> getAuthenticationURIs() {
        return authenticationURIs;
    }

    public void setAuthenticationURIs(Map<String, String> authenticationURIs) {
        this.authenticationURIs = authenticationURIs;
    }

    @XmlElementWrapper(name = "tokenTypesOffered")
    public List<String> getTokenTypesOffered() {
        return tokenTypesOffered;
    }

    public void setTokenTypesOffered(List<String> tokenTypesOffered) {
        this.tokenTypesOffered = tokenTypesOffered;
    }

    @XmlElementWrapper(name = "claimTypesOffered")
    @XmlElementRef(name = "claimType")
    public List<Claim> getClaimTypesOffered() {
        return claimTypesOffered;
    }

    public void setClaimTypesOffered(List<Claim> claimTypesOffered) {
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

    public boolean isRpSingleSignOutConfirmation() {
        return rpSingleSignOutConfirmation;
    }

    public void setRpSingleSignOutConfirmation(boolean rpSingleSignOutConfirmation) {
        this.rpSingleSignOutConfirmation = rpSingleSignOutConfirmation;
    }

    public boolean isRpSingleSignOutCleanupConfirmation() {
        return rpSingleSignOutCleanupConfirmation;
    }

    public void setRpSingleSignOutCleanupConfirmation(boolean rpSingleSignOutCleanupConfirmation) {
        this.rpSingleSignOutCleanupConfirmation = rpSingleSignOutCleanupConfirmation;
    }

}
