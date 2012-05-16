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

import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;
import org.apache.cxf.fediz.core.config.jaxb.AuthenticationType;

public class Authentication {
    private AuthenticationType authType;

    public Authentication(AuthenticationType authType) {
        super();
        this.authType = authType;
    }

    protected AuthenticationType getAuthType() {
        return authType;
    }

    protected void setAuthType(AuthenticationType authType) {
        this.authType = authType;
    }

    public PropertyType getType() {
        return PropertyType.fromValue(authType.getType().value());
    }

    public int hashCode() {
        return authType.hashCode();
    }

    public void setType(PropertyType value) {
        authType.setType(ArgumentType.fromValue(value.value()));
    }

    public String getValue() {
        return authType.getValue();
    }

    public void setValue(String value) {
        authType.setValue(value);
    }

    public boolean equals(Object obj) {
        return authType.equals(obj);
    }

    public String toString() {
        return authType.toString();
    }
 
}
