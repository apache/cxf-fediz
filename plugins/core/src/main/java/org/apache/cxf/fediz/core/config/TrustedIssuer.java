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

import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;

public class TrustedIssuer {
    private TrustedIssuerType trustedIssuerType = null;

        
    public TrustedIssuer(TrustedIssuerType trustedIssuerType) {
        super();
        this.trustedIssuerType = trustedIssuerType;
    }
    
    public String getName() {
        return trustedIssuerType.getName();
    }
    
    public void setName(String name) {
        trustedIssuerType.setName(name);
    }
    
    public String getSubject() {
        return trustedIssuerType.getSubject();
    }
    
    public void setSubject(String subject) {
        trustedIssuerType.setSubject(subject);
    }

    public CertificateValidationMethod getCertificateValidationMethod() {
        if (ValidationType.CHAIN_TRUST.equals(trustedIssuerType.getCertificateValidation())) {
            return CertificateValidationMethod.CHAIN_TRUST;
        } else if (ValidationType.PEER_TRUST.equals(trustedIssuerType.getCertificateValidation())) {
            return CertificateValidationMethod.PEER_TRUST;
        } else {
            throw new IllegalStateException("Not supported certificate validation type");
        }
    }
    
    public void setCertificateValidationMethod(CertificateValidationMethod validationMethod) {
        if (CertificateValidationMethod.CHAIN_TRUST.equals(validationMethod)) {
            trustedIssuerType.setCertificateValidation(ValidationType.CHAIN_TRUST);
        } else if (CertificateValidationMethod.PEER_TRUST.equals(validationMethod)) {
            trustedIssuerType.setCertificateValidation(ValidationType.PEER_TRUST);
        } else {
            throw new IllegalStateException("Not supported certificate validation type");
        }
    }
    
    

   public int hashCode() {
        return trustedIssuerType.hashCode();
    }
    
    public boolean equals(Object obj) {
        return trustedIssuerType.equals(obj);
    }

    public String toString() {
        return trustedIssuerType.toString();
    }
    

}
