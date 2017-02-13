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

import org.apache.cxf.fediz.core.config.jaxb.ValidationType;

public enum CertificateValidationMethod {

    PEER_TRUST("PeerTrust"),
    CHAIN_TRUST("ChainTrust");

    private final String value;

    CertificateValidationMethod(String v) {
        value = v;
    }
    CertificateValidationMethod(ValidationType type) {
        value = type.value();
    }

    public String value() {
        return value;
    }

    public static CertificateValidationMethod fromValue(String v) {
        for (CertificateValidationMethod c: CertificateValidationMethod.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }



}
