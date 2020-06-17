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

package org.apache.cxf.fediz.core;

import java.security.cert.Certificate;
import java.util.Arrays;

import org.w3c.dom.Element;

public class TokenValidatorRequest {

    private final Element token;
    private final Certificate[] certs;
    private boolean enforceTokenSigned = true;

    public TokenValidatorRequest(Element token, Certificate[] certs) {
        this.token = token;
        if (certs != null) {
            this.certs = Arrays.copyOf(certs, certs.length);
        } else {
            this.certs = null;
        }
    }

    public Element getToken() {
        return token;
    }

    public Certificate[] getCerts() {
        if (certs != null) {
            return Arrays.copyOf(certs, certs.length);
        }
        return null;
    }
    
    public void setEnforceTokenSigned(boolean enforceTokenSigned) {
        this.enforceTokenSigned = enforceTokenSigned;
    }
    
    public boolean isEnforceTokenSigned() {
        return this.enforceTokenSigned;
    }
}
