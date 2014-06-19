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

import javax.security.auth.callback.CallbackHandler;

import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;
import org.apache.cxf.fediz.core.config.jaxb.CallbackType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.util.ClassLoaderUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Protocol {
    private static final Logger LOG = LoggerFactory.getLogger(Protocol.class);
                                                              
    private ProtocolType protocolType;
    private ClassLoader classloader;
    private Object issuer;

    public Protocol(ProtocolType protocolType) {
        super();
        this.protocolType = protocolType;
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
        return protocolType.equals(obj);
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

    public Object getIssuer() {
        if (this.issuer != null) {
            return this.issuer;
        }
        CallbackType cbt = getProtocolType().getIssuer();
        this.issuer = loadCallbackType(cbt, "Issuer");
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
    
    protected Object loadCallbackType(CallbackType cbt, String name) {
        if (cbt == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            return new String(cbt.getValue());
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            try {
                if (getClassloader() == null) {
                    return ClassLoaderUtils.loadClass(cbt.getValue(), this.getClass()).newInstance();
                } else {
                    return getClassloader().loadClass(cbt.getValue()).newInstance();
                }
            } catch (Exception e) {
                LOG.error("Failed to create instance of " + cbt.getValue(), e);
                throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
            }            
        } else {
            LOG.error("Only String and Class are supported for '" + name + "'");
            throw new IllegalStateException("Only String and Class are supported for '" + name + "'");
        }
    }

}
