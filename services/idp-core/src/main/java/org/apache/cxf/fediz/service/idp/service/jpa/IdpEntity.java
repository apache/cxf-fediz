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

package org.apache.cxf.fediz.service.idp.service.jpa;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToMany;
import javax.persistence.MapKeyColumn;
import javax.validation.constraints.NotNull;

import org.apache.openjpa.persistence.jdbc.Index;

@Entity(name = "IDP")
public class IdpEntity {

    @Id
    private int id;

    // Unique
    // fed:TargetScope
    @Index
    @NotNull
    private String realm; // wtrealm, whr

    // Unique
    // https://<host>:<port>/fediz-idp/<IDP uri>/
    private String uri;

    // Home Realm Discovery Service
    // Spring EL
    private String hrds;

    // if HRDS can't determine the home realm, should
    // the list of trusted IDPs be shown to make a choice
    private boolean provideIdpList;

    // If HRDS can't discover a home realm and displaying IDP list is not
    // enabled
    // it falls back to current IDP if an authentication domain is configured
    private boolean useCurrentIdp;

    // Store certificate in DB or filesystem, provide options?
    // md:KeyDescriptor, use="signing"
    private String certificate;

    // Password to read the private key to sign metadata document
    private String certificatePassword;

    // fed:SecurityTokenSerivceEndpoint
    @NotNull
    private URL stsUrl;

    // fedl:PassiveRequestorEndpoint
    // published hostname, port must be configured
    @NotNull
    private URL idpUrl;

    private boolean rpSingleSignOutConfirmation;

    // RoleDescriptor protocolSupportEnumeration=
    // "http://docs.oasis-open.org/wsfed/federation/200706"
    // "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    // Could be more in the future

    @ElementCollection
    @CollectionTable(name = "idp_protocols")
    @Column(name = "protocol")
    private List<String> supportedProtocols = new ArrayList<>();

    // list of RPs and RP-IDPs from whom we accept SignInResponse
    // which includes RP IDPs
    // key: wtrealm
    @ManyToMany(cascade = CascadeType.ALL)
    private List<ApplicationEntity> applications = new ArrayList<>();

    // list of trusted IDP from whom we accept SignInResponse
    // key: whr
    @ManyToMany(cascade = CascadeType.ALL)
    private List<TrustedIdpEntity> trustedIdps = new ArrayList<>();

    // which URI to redirect for authentication
    // fediz-idp/<IDP uri>/login/auth/<auth URI>
    // wauth to auth URI mapping
    @ElementCollection
    @MapKeyColumn(name = "name")
    @Column(name = "value")
    @CollectionTable(name = "idp_auth_uris", joinColumns = @JoinColumn(name = "idp_id"))
    private Map<String, String> authenticationURIs = new HashMap<>();

    // required to create Federation Metadata document
    // fed:TokenTypesOffered
    //[TODO] Tokens could be managed independently, but no real impact in IDP at runtime
    //       Only informational purpose for metadata document, but required in STS
    @ElementCollection
    @CollectionTable(name = "idp_tokentypes")
    @Column(name = "tokentype")
    private List<String> tokenTypesOffered = new ArrayList<>();

    // fed:ClaimTypesOffered
    @ManyToMany(cascade = CascadeType.ALL)
    private List<ClaimEntity> claimTypesOffered = new ArrayList<>();

    // ServiceDisplayName
    @NotNull
    private String serviceDisplayName;

    // ServiceDescription
    private String serviceDescription;

    private boolean rpSingleSignOutCleanupConfirmation;

    private boolean automaticRedirectToRpAfterLogout;

    private boolean disableLogoutAddressValidation;


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

    public List<String> getSupportedProtocols() {
        return supportedProtocols;
    }

    public void setSupportedProtocols(List<String> supportedProtocols) {
        this.supportedProtocols = supportedProtocols;
    }

    public List<ApplicationEntity> getApplications() {
        return applications;
    }

    public void setApplications(List<ApplicationEntity> applications) {
        this.applications = applications;
    }

    public List<TrustedIdpEntity> getTrustedIdps() {
        return trustedIdps;
    }

    public void setTrustedIdps(List<TrustedIdpEntity> trustedIdps) {
        this.trustedIdps = trustedIdps;
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

    public List<ClaimEntity> getClaimTypesOffered() {
        return claimTypesOffered;
    }

    public void setClaimTypesOffered(List<ClaimEntity> claimTypesOffered) {
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

    public boolean isAutomaticRedirectToRpAfterLogout() {
        return automaticRedirectToRpAfterLogout;
    }

    public void setAutomaticRedirectToRpAfterLogout(boolean automaticRedirectToRpAfterLogout) {
        this.automaticRedirectToRpAfterLogout = automaticRedirectToRpAfterLogout;
    }

    public boolean isDisableLogoutAddressValidation() {
        return disableLogoutAddressValidation;
    }

    public void setDisableLogoutAddressValidation(boolean disableLogoutAddressValidation) {
        this.disableLogoutAddressValidation = disableLogoutAddressValidation;
    }

}
