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

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.OpenSAMLUtil;

/**
 * Some SAML Utility methods
 */
public final class SAMLUtil  {
    
    private SAMLUtil() {
        // complete
    }

    /**
     * Check the holder-of-key requirements against the received assertion. The subject
     * credential of the SAML Assertion must match a client certificate credential when 
     * 2-way TLS is used.
     * @param assertionWrapper the SAML Assertion wrapper object
     * @tlsCerts The client certificates
     * @param signedResults a list of all of the signed results
     */
    public static boolean checkHolderOfKey(
        AssertionWrapper assertionWrapper,
        Certificate[] tlsCerts
    ) {
        List<String> confirmationMethods = assertionWrapper.getConfirmationMethods();
        for (String confirmationMethod : confirmationMethods) {
            if (OpenSAMLUtil.isMethodHolderOfKey(confirmationMethod)) {
                if (tlsCerts == null || tlsCerts.length == 0) {
                    return false;
                }
                SAMLKeyInfo subjectKeyInfo = assertionWrapper.getSubjectKeyInfo();
                if (!compareCredentials(subjectKeyInfo, tlsCerts)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Compare the credentials of the assertion to the credentials used in 2-way TLS.
     * Return true on a match
     * @param subjectKeyInfo the SAMLKeyInfo object
     * @param signedResults a list of all of the signed results
     * @return true if the credentials of the assertion were used to verify a signature
     */
    private static boolean compareCredentials(
        SAMLKeyInfo subjectKeyInfo,
        Certificate[] tlsCerts
    ) {
        X509Certificate[] subjectCerts = subjectKeyInfo.getCerts();
        PublicKey subjectPublicKey = subjectKeyInfo.getPublicKey();

        //
        // Try to match the TLS certs
        //
        if (subjectCerts != null && subjectCerts.length > 0 
            && tlsCerts[0].equals(subjectCerts[0])) {
            return true;
        } else if (subjectPublicKey != null
            && tlsCerts[0].getPublicKey().equals(subjectPublicKey)) {
            return true;
        }

        return false;
    }

}
