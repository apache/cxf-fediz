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
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "application", namespace = "http://org.apache.cxf.fediz/")
@XmlType(propOrder = {"realm", "role", "serviceDisplayName", "serviceDescription", "protocol",
                      "tokenType", "lifeTime", "encryptionCertificate", "requestedClaims",
                      "policyNamespace", "passiveRequestorEndpoint", "passiveRequestorEndpointConstraint", "id",
                      "validatingCertificate", "enableAppliesTo", "logoutEndpoint", "logoutEndpointConstraint"})
public class Application implements Serializable {

    private static final long serialVersionUID = 5644327504861846964L;



    protected int id;


    //Could be imported from Metadata document or manually filled

    //@Column(name = "REALM", nullable = true, length = FIELD_LENGTH)
    protected String realm;  //wtrealm, whr

    //Could be read from Metadata, RoleDescriptor protocolSupportEnumeration=
    // "http://docs.oasis-open.org/wsfed/federation/200706"
    // Metadata could provide more than one but one must be chosen
    protected String protocol;

    // Public key only
    // Could be read from Metadata, md:KeyDescriptor, use="encryption"
    protected String encryptionCertificate;

    // Certificate for Signature verification
    protected String validatingCertificate;

    // Could be read from Metadata, fed:ClaimTypesRequested
    protected List<RequestClaim> requestedClaims = new ArrayList<>();

    //Could be read from Metadata, ServiceDisplayName
    //usage for list of application where user is logged in
    protected String serviceDisplayName;

    //Could be read from Metadata, ServiceDescription
    //usage for list of application where user is logged in
    protected String serviceDescription;

    //Could be read from Metadata, RoleDescriptor
    //fed:ApplicationServiceType, fed:SecurityTokenServiceType
    protected String role;

    // Not in Metadata, configured in IDP or passed in wreq parameter
    protected String tokenType;

    // Not in Metadata, configured in IDP or passed in wreq parameter
    protected int lifeTime;

    // WS-Policy Namespace for AppliesTo element
    protected String policyNamespace;

    // Request audience restriction in token for this application (default is true)
    private boolean enableAppliesTo = true;

    private URI href;

    //Could be read from Metadata, PassiveRequestorEndpoint
    //fed:ApplicationServiceType, fed:SecurityTokenServiceType
    private String passiveRequestorEndpoint;

    // A regular expression constraint on the passiveRequestorEndpoint
    private String passiveRequestorEndpointConstraint;
    private Pattern compiledPassiveRequestorEndpointConstraint;

    private String logoutEndpoint;

    // A regular expression constraint on the logoutEndpoint
    private String logoutEndpointConstraint;
    private Pattern compiledLogoutEndpointConstraint;


    @XmlAttribute
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @XmlAttribute
    public URI getHref() {
        return href;
    }

    public void setHref(URI href) {
        this.href = href;
    }

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

    @XmlElementWrapper(name = "claims")
    @XmlElementRef(name = "requestedClaims")
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

    public int getLifeTime() {
        return lifeTime;
    }

    public void setLifeTime(int lifeTime) {
        this.lifeTime = lifeTime;
    }

    public String getPolicyNamespace() {
        return policyNamespace;
    }

    public void setPolicyNamespace(String policyNamespace) {
        this.policyNamespace = policyNamespace;
    }

    public String getPassiveRequestorEndpoint() {
        return passiveRequestorEndpoint;
    }

    public void setPassiveRequestorEndpoint(String passiveRequestorEndpoint) {
        this.passiveRequestorEndpoint = passiveRequestorEndpoint;
    }

    public String getPassiveRequestorEndpointConstraint() {
        return passiveRequestorEndpointConstraint;
    }

    public void setPassiveRequestorEndpointConstraint(String passiveRequestorEndpointConstraint) {
        this.passiveRequestorEndpointConstraint = passiveRequestorEndpointConstraint;
        if (passiveRequestorEndpointConstraint != null) {
            compiledPassiveRequestorEndpointConstraint = Pattern.compile(passiveRequestorEndpointConstraint);
        } else {
            compiledPassiveRequestorEndpointConstraint = null;
        }
    }

    public Pattern getCompiledPassiveRequestorEndpointConstraint() {
        return compiledPassiveRequestorEndpointConstraint;
    }

    public String getValidatingCertificate() {
        return validatingCertificate;
    }

    public void setValidatingCertificate(String validatingCertificate) {
        this.validatingCertificate = validatingCertificate;
    }

    public boolean isEnableAppliesTo() {
        return enableAppliesTo;
    }

    public void setEnableAppliesTo(boolean useAudienceRestriction) {
        this.enableAppliesTo = useAudienceRestriction;
    }

    public String getLogoutEndpoint() {
        return logoutEndpoint;
    }

    public void setLogoutEndpoint(String logoutEndpoint) {
        this.logoutEndpoint = logoutEndpoint;
    }

    public String getLogoutEndpointConstraint() {
        return logoutEndpointConstraint;
    }

    public void setLogoutEndpointConstraint(String logoutEndpointConstraint) {
        this.logoutEndpointConstraint = logoutEndpointConstraint;
        if (logoutEndpointConstraint != null) {
            compiledLogoutEndpointConstraint = Pattern.compile(logoutEndpointConstraint);
        } else {
            compiledLogoutEndpointConstraint = null;
        }
    }

    public Pattern getCompiledLogoutEndpointConstraint() {
        return compiledLogoutEndpointConstraint;
    }
}
