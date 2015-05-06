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

package org.apache.cxf.fediz.core.saml;

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Pattern;

import org.apache.cxf.fediz.core.saml.FedizSignatureTrustValidator.TrustType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.validate.Credential;

/**
 * This class validates a SAML Assertion by wrapping the default WSS4J SamlAssertionValidator.
 * It extends it by verifying trust in the Signature using a TRUST_TYPE, as well as subject DN
 * constraints.
 */
public class SamlAssertionValidator extends org.apache.wss4j.dom.validate.SamlAssertionValidator {
    
    private TrustType signatureTrustType = TrustType.CHAIN_TRUST;
        
    /**
     * a collection of compiled regular expression patterns for the subject DN
     */
    private Collection<Pattern> subjectDNPatterns = new ArrayList<>();
    
    /**
     * Set a list of Strings corresponding to regular expression constraints on
     * the subject DN of a certificate
     */
    public void setSubjectConstraints(Collection<Pattern> constraints) {
        if (constraints != null) {
            subjectDNPatterns.clear();
            subjectDNPatterns.addAll(constraints);
        }
    }
    
    /**
     * Set the kind of trust. The default is CHAIN_TRUST.
     */
    public void setSignatureTrustType(TrustType trustType) {
        this.signatureTrustType = trustType;
    }

    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     * @param assertion The signed Assertion
     * @param data The RequestData context
     * @return A Credential instance
     * @throws WSSecurityException
     */
    @Override
    protected Credential verifySignedAssertion(
        SamlAssertionWrapper assertion,
        RequestData data
    ) throws WSSecurityException {
        Credential credential = new Credential();
        SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
        credential.setPublicKey(samlKeyInfo.getPublicKey());
        credential.setCertificates(samlKeyInfo.getCerts());
        
        FedizSignatureTrustValidator trustValidator = new FedizSignatureTrustValidator();
        trustValidator.setSignatureTrustType(signatureTrustType);
        trustValidator.setSubjectConstraints(subjectDNPatterns);
        
        return trustValidator.validate(credential, data);
    }

    
}
