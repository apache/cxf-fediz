/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cxf.fediz.core.config;

import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.fediz.core.config.jaxb.ClaimType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimTypesRequested;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;

public class FederationProtocol extends Protocol {

    public FederationProtocol(ProtocolType protocolType) {
        super(protocolType);
    }

    protected FederationProtocolType getFederationProtocol() {
        return (FederationProtocolType)super.getProtocolType();
    }

    protected void setFederationProtocol(FederationProtocolType federationProtocol) {
        super.setProtocolType(federationProtocol);
    }

    public int hashCode() {
        return getFederationProtocol().hashCode();
    }

    public String getRealm() {
        return getFederationProtocol().getRealm();
    }

    public void setRealm(String value) {
        getFederationProtocol().setRealm(value);
    }

    public String getIssuer() {
        return getFederationProtocol().getIssuer();
    }

    public boolean equals(Object obj) {
        return getFederationProtocol().equals(obj);
    }

    public void setIssuer(String value) {
        getFederationProtocol().setIssuer(value);
    }

    public String getRoleDelimiter() {
        return getFederationProtocol().getRoleDelimiter();
    }

    public void setRoleDelimiter(String value) {
        getFederationProtocol().setRoleDelimiter(value);
    }

    public String getRoleURI() {
        return getFederationProtocol().getRoleURI();
    }

    public void setRoleURI(String value) {
        getFederationProtocol().setRoleURI(value);
    }

    public Authentication getAuthenticationType() {
        return new Authentication(getFederationProtocol().getAuthenticationType());
    }

    public void setAuthenticationType(Authentication value) {
        getFederationProtocol().setAuthenticationType(value.getAuthType());
    }

    public HomeRealm getHomeRealm() {
        return new HomeRealm(getFederationProtocol().getHomeRealm());
    }

    public void setHomeRealm(HomeRealm value) {
        getFederationProtocol().setHomeRealm(value.getHomeRealm());
    }

    public String getFreshness() {
        return getFederationProtocol().getFreshness();
    }

    public void setFreshness(String value) {
        getFederationProtocol().setFreshness(value);
    }

    public String getReply() {
        return getFederationProtocol().getReply();
    }

    public void setReply(String value) {
        getFederationProtocol().setReply(value);
    }

    public String getRequest() {
        return getFederationProtocol().getRequest();
    }

    public void setRequest(String value) {
        getFederationProtocol().setRequest(value);
    }

    public List<Claim> getClaimTypesRequested() {
        ClaimTypesRequested claimsRequested = getFederationProtocol().getClaimTypesRequested();
        List<Claim> claims = new ArrayList<Claim>();
        for(ClaimType c:claimsRequested.getClaimType() ){
            claims.add(new Claim(c));
        }
        return claims;
    }

    public void setClaimTypesRequested(ClaimTypesRequested value) {
        getFederationProtocol().setClaimTypesRequested(value);
    }

    public List<String> getSecurityTokenValidators() {
        return getFederationProtocol().getSecurityTokenValidators();
    }

    public String getVersion() {
        return getFederationProtocol().getVersion();
    }

    public void setVersion(String value) {
        getFederationProtocol().setVersion(value);
    }

    public String toString() {
        return getFederationProtocol().toString();
    }

}
