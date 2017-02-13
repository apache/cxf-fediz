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
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "trustedIdp", namespace = "http://org.apache.cxf.fediz/")
@XmlType(propOrder = {"realm", "issuer", "url", "name", "description", "protocol", "trustType",
                      "certificate", "federationType", "cacheTokens", "logo", "id", "parameters" })
//@XmlAttribute on Id must be set on getter, not on attribute, otherwise error
public class TrustedIdp implements Serializable {

    private static final long serialVersionUID = -6520081722646469178L;


    protected int id;

    //@Column(name = "REALM", nullable = true, length = FIELD_LENGTH)
    protected String realm;  //wtrealm, whr

    //@Column(name = "Issuer", nullable = true, length = FIELD_LENGTH)
    protected String issuer;  //SAMLResponse issuer name

    // Should tokens be cached from trusted IDPs
    // to avoid redirection to the trusted IDP again for next SignIn request
    protected boolean cacheTokens;

    //Could be read from Metadata, PassiveRequestorEndpoint
    protected String url;

    //Could be read from Metadata, md:KeyDescriptor, use="signing"
    //Store certificate in DB or filesystem, provide options?
    protected String certificate;

    //Direct trust (signing cert imported), Indirect trust (CA certs imported, subject configured)
    protected TrustType trustType;

    //Could be read from Metadata, RoleDescriptor protocolSupportEnumeration=
    // "http://docs.oasis-open.org/wsfed/federation/200706"
    // Metadata could provide more than one but one must be chosen
    protected String protocol;

    //FederateIdentity, FederateClaims
    protected FederationType federationType;

    //optional (to provide a list of IDPs)
    protected String name;

    //optional (to provide a list of IDPs)
    protected String description;

    //optional (to provide a list of IDPs)
    protected String logo;

    // Additional (possibly protocol specific parameters)
    protected Map<String, String> parameters = new HashMap<>();


    @XmlAttribute
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public boolean isCacheTokens() {
        return cacheTokens;
    }

    public void setCacheTokens(boolean cacheTokens) {
        this.cacheTokens = cacheTokens;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public FederationType getFederationType() {
        return federationType;
    }

    public void setFederationType(FederationType federationType) {
        this.federationType = federationType;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
    }

    public TrustType getTrustType() {
        return trustType;
    }

    public void setTrustType(TrustType trustType) {
        this.trustType = trustType;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }


}
