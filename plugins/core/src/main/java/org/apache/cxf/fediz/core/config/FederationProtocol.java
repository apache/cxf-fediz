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

package org.apache.cxf.fediz.core.config;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;
import org.apache.cxf.fediz.core.config.jaxb.CallbackType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimTypesRequested;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FederationProtocol extends Protocol {

    private static final Logger LOG = LoggerFactory.getLogger(FederationProtocol.class);
    
    private Object authenticationType;
    private Object issuer;
    private Object homeRealm;
    
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

    public boolean equals(Object obj) {
        return getFederationProtocol().equals(obj);
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

    public Object getAuthenticationType() {
        if (this.authenticationType != null) {
            return this.authenticationType;
        }
        CallbackType cbt = getFederationProtocol().getAuthenticationType();
        if (cbt.getType().equals(ArgumentType.STRING)) {
            this.authenticationType = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                this.authenticationType = 
                    Thread.currentThread().getContextClassLoader().loadClass(cbt.getValue()).newInstance();
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }            
        } else {
            LOG.error("Only String and Class are supported for 'AuthenticationType'");
            throw new IllegalStateException("Only String and Class are supported for AuthenticationType");
        }
        return this.authenticationType;
    }

    public void setAuthenticationType(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.authenticationType = value;
        } else {
            LOG.error("Unsupported 'AuthenticationType' object");
            throw new IllegalArgumentException("Unsupported 'AuthenticationType' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
    }
    
    public Object getHomeRealm() {
        if (this.homeRealm != null) {
            return this.homeRealm;
        }
        CallbackType cbt = getFederationProtocol().getHomeRealm();
        if (cbt.getType().equals(ArgumentType.STRING)) {
            this.homeRealm = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                this.homeRealm =
                    Thread.currentThread().getContextClassLoader().loadClass(cbt.getValue()).newInstance();
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }            
        } else {
            LOG.error("Only String and Class are supported for 'HomeRealm'");
            throw new IllegalStateException("Only String and Class are supported for 'HomeRealm'");
        }
        return this.homeRealm;
    }

    public void setHomeRealm(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.homeRealm = value;
        } else {
            LOG.error("Unsupported 'HomeRealm' object");
            throw new IllegalArgumentException("Unsupported 'HomeRealm' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
    }
    
    public Object getIssuer() {
        if (this.issuer != null) {
            return this.issuer;
        }
        CallbackType cbt = getFederationProtocol().getIssuer();
        if (cbt.getType().equals(ArgumentType.STRING)) {
            this.issuer = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                this.issuer = 
                    Thread.currentThread().getContextClassLoader().loadClass(cbt.getValue()).newInstance();
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }
        } else {
            LOG.error("Only String and Class are supported for 'Issuer'");
            throw new IllegalStateException("Only String and Class are supported for 'Issuer'");
        }
        return this.issuer;
    }

    public void setIssuer(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.issuer = value;
        } else {
            LOG.error("Unsupported 'Issuer' object");
            throw new IllegalArgumentException("Unsupported 'Issuer' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
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
        for (ClaimType c:claimsRequested.getClaimType()) {
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
