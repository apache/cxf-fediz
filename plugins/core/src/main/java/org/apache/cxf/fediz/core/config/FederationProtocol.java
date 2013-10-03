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

import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;
import org.apache.cxf.fediz.core.config.jaxb.CallbackType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimType;
import org.apache.cxf.fediz.core.config.jaxb.ClaimTypesRequested;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.saml.SAMLTokenValidator;
import org.apache.cxf.fediz.core.util.ClassLoaderUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FederationProtocol extends Protocol {

    private static final Logger LOG = LoggerFactory.getLogger(FederationProtocol.class);
    
    private Object authenticationType;
    private Object issuer;
    private Object homeRealm;
    private Object freshness;
    private Object signInQuery;
    private Object realm;
    private List<TokenValidator> validators = new ArrayList<TokenValidator>();
    private ClassLoader classloader;
    
    
    public FederationProtocol(ProtocolType protocolType) {
        super(protocolType);
        
        FederationProtocolType fp = (FederationProtocolType)protocolType;
        if (fp.getTokenValidators() != null && fp.getTokenValidators().getValidator() != null) {
            for (String validatorClassname : fp.getTokenValidators().getValidator()) {
                Object obj = null;
                try {
                    if (this.classloader == null) {
                        obj = ClassLoaderUtils.loadClass(validatorClassname, this.getClass()).newInstance();
                    } else {
                        obj = this.classloader.loadClass(validatorClassname).newInstance();
                    }
                } catch (Exception ex) {
                    LOG.error("Failed to instantiate TokenValidator implementation class: '"
                              + validatorClassname + "'\n" + ex.getClass().getCanonicalName() + ": " + ex.getMessage());
                }
                if (obj instanceof TokenValidator) {
                    validators.add((TokenValidator)obj);
                } else if (obj != null) {
                    LOG.error("Invalid TokenValidator implementation class: '" + validatorClassname + "'");
                }
            }
        }
        
        // add SAMLTokenValidator as the last one
        // Fediz chooses the first validator in the list if its
        // canHandleToken or canHandleTokenType method return true
        SAMLTokenValidator validator = new SAMLTokenValidator();
        validators.add(validators.size(), validator);
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

    public Object getRealm() {
        if (this.realm != null) {
            return this.realm;
        }
        CallbackType cbt = getFederationProtocol().getRealm();
        if (cbt == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            this.realm = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (this.classloader == null) {
                    this.realm = ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    this.realm = this.classloader.loadClass(cbt.getValue()).newInstance();
                }
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }            
        } else {
            LOG.error("Only String and Class are supported for 'Realm'");
            throw new IllegalStateException("Only String and Class are supported for 'Realm'");
        }
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
    
    public String getApplicationServiceURL() {
        return getFederationProtocol().getApplicationServiceURL();
    }

    public void setApplicationServiceURL(String value) {
        getFederationProtocol().setApplicationServiceURL(value);
    }

    public Object getAuthenticationType() {
        if (this.authenticationType != null) {
            return this.authenticationType;
        }
        CallbackType cbt = getFederationProtocol().getAuthenticationType();
        if (cbt == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            this.authenticationType = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (this.classloader == null) {
                    this.authenticationType = ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    this.authenticationType = this.classloader.loadClass(cbt.getValue()).newInstance();
                }
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
        if (cbt == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            this.homeRealm = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (this.classloader == null) {
                    this.homeRealm = ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    this.homeRealm = this.classloader.loadClass(cbt.getValue()).newInstance();
                }
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
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            this.issuer = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (this.classloader == null) {
                    this.issuer = ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    this.issuer = this.classloader.loadClass(cbt.getValue()).newInstance();
                }
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
    
    public Object getFreshness() {
        if (this.freshness != null) {
            return this.freshness;
        }
        CallbackType cbt = getFederationProtocol().getFreshness();
        if (cbt == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            this.freshness = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (this.classloader == null) {
                    this.freshness = ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    this.freshness = this.classloader.loadClass(cbt.getValue()).newInstance();
                }
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }            
        } else {
            LOG.error("Only String and Class are supported for 'Freshness'");
            throw new IllegalStateException("Only String and Class are supported for 'Freshness'");
        }
        return this.freshness;
    }

    public void setFreshness(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.freshness = value;
        } else {
            LOG.error("Unsupported 'Freshness' object");
            throw new IllegalArgumentException("Unsupported 'Freshness' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
    }
    
    public Object getSignInQuery() {
        if (this.signInQuery != null) {
            return this.signInQuery;
        }
        CallbackType cbt = getFederationProtocol().getSignInQuery();
        if (cbt == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            this.signInQuery = new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (this.classloader == null) {
                    this.signInQuery = ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    this.signInQuery = this.classloader.loadClass(cbt.getValue()).newInstance();
                }
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }            
        } else {
            LOG.error("Only String and Class are supported for 'SignInQuery'");
            throw new IllegalStateException("Only String and Class are supported for 'SignInQuery'");
        }
        return this.signInQuery;
    }

    public void setSignInQuery(Object value) {
        final boolean isString = value instanceof String;
        final boolean isCallbackHandler = value instanceof CallbackHandler;
        if (isString || isCallbackHandler) {
            this.signInQuery = value;
        } else {
            LOG.error("Unsupported 'SignInQuery' object");
            throw new IllegalArgumentException("Unsupported 'SignInQuery' object. Type must be "
                                               + "java.lang.String or javax.security.auth.callback.CallbackHandler.");
        }
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

    public List<TokenValidator> getTokenValidators() {
        return validators;
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
    
    public ClassLoader getClassloader() {
        return classloader;
    }

    public void setClassloader(ClassLoader classloader) {
        this.classloader = classloader;
    }

}
