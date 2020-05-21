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
import java.util.Objects;

import javax.security.auth.callback.CallbackHandler;

import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.config.jaxb.CallbackType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimTypesRequested;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.util.ClassLoaderUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Protocol {
    private static final Logger LOG = LoggerFactory.getLogger(Protocol.class);

    private ProtocolType protocolType;
    private ClassLoader classloader;
    private Object issuer;
    private Object realm;
    private List<TokenValidator> validators = new ArrayList<>();
    private Object reply;

    public Protocol(ProtocolType protocolType) {
        this.protocolType = protocolType;

        if (protocolType.getTokenValidators() != null && protocolType.getTokenValidators().getValidator() != null) {
            for (String validatorClassname : protocolType.getTokenValidators().getValidator()) {
                try {
                    Object obj = ClassLoaderUtils.loadClass(validatorClassname, this.getClass()).newInstance();
                    if (obj instanceof TokenValidator) {
                        validators.add((TokenValidator)obj);
                    } else {
                        LOG.error("Invalid TokenValidator implementation class: '" + validatorClassname + "'");
                    }
                } catch (Exception ex) {
                    LOG.error("Failed to instantiate TokenValidator implementation class: '"
                              + validatorClassname + "'\n" + ex.getClass().getCanonicalName() + ": " + ex.getMessage());
                }
            }
        }
    }

    protected ProtocolType getProtocolType() {
        return protocolType;
    }

    protected void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
    }

    public int hashCode() {
        return protocolType.hashCode();
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof Protocol)) {
            return false;
        }
        return Objects.equals(protocolType, ((Protocol) obj).getProtocolType());
    }

    public String toString() {
        return protocolType.toString();
    }

    public ClassLoader getClassloader() {
        return classloader;
    }

    public void setClassloader(ClassLoader classloader) {
        this.classloader = classloader;
    }

    public String getRoleDelimiter() {
        return getProtocolType().getRoleDelimiter();
    }

    public void setRoleDelimiter(String value) {
        getProtocolType().setRoleDelimiter(value);
    }

    public String getRoleURI() {
        return getProtocolType().getRoleURI();
    }

    public void setRoleURI(String value) {
        getProtocolType().setRoleURI(value);
    }

    public String getMetadataURI() {
        return getProtocolType().getMetadataURI();
    }

    public void setMetadataURI(String value) {
        getProtocolType().setMetadataURI(value);
    }

    public Object getIssuer() {
        if (this.issuer != null) {
            return this.issuer;
        }
        CallbackType cbt = getProtocolType().getIssuer();
        this.issuer = ConfigUtils.loadCallbackType(cbt, "Issuer", getClassloader());
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

    public Object getRealm() {
        if (this.realm != null) {
            return this.realm;
        }
        CallbackType cbt = getProtocolType().getRealm();
        this.realm = ConfigUtils.loadCallbackType(cbt, "Realm", getClassloader());
        return this.realm;
    }

    public void setRealm(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.realm = value;
        } else {
            LOG.error("Unsupported 'Realm' object");
            throw new IllegalArgumentException("Unsupported 'Realm' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
    }

    public List<TokenValidator> getTokenValidators() {
        return validators;
    }

    public List<Claim> getClaimTypesRequested() {
        ClaimTypesRequested claimsRequested = getProtocolType().getClaimTypesRequested();
        List<Claim> claims = new ArrayList<>();
        if (claimsRequested != null) {
            for (ClaimType c : claimsRequested.getClaimType()) {
                claims.add(new Claim(c));
            }
        }
        return claims;
    }

    public void setClaimTypesRequested(ClaimTypesRequested value) {
        getProtocolType().setClaimTypesRequested(value);
    }

    public String getApplicationServiceURL() {
        return getProtocolType().getApplicationServiceURL();
    }

    public void setApplicationServiceURL(String value) {
        getProtocolType().setApplicationServiceURL(value);
    }

    public Object getReply() {
        if (this.reply != null) {
            return this.reply;
        }
        CallbackType cbt = getProtocolType().getReply();
        this.reply = ConfigUtils.loadCallbackType(cbt, "Reply", getClassloader());
        return this.reply;
    }

    public void setReply(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.reply = value;
        } else {
            LOG.error("Unsupported 'Reply' object");
            throw new IllegalArgumentException("Unsupported 'Reply' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
    }

}
