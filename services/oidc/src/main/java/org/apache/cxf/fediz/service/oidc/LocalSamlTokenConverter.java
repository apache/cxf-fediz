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
package org.apache.cxf.fediz.service.oidc;

import org.w3c.dom.Element;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;



public class LocalSamlTokenConverter implements SamlTokenConverter {

    @Override
    public IdToken convertToIdToken(Element samlToken, 
                                    String subjectName, 
                                    ClaimCollection claims,
                                    String clientId,
                                    String nonce) {
        IdToken idToken = new IdToken();
        idToken.setSubject(subjectName);
        idToken.setAudience(clientId);
        idToken.setIssuer("accounts.fediz.com");
        
        long currentTimeInSeconds = System.currentTimeMillis() / 1000L;
        idToken.setIssuedAt(currentTimeInSeconds);
        idToken.setExpiryTime(currentTimeInSeconds + 60000L);
        
        // Set the authInstant
        try {
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(samlToken);
            
            if (wrapper.getSaml2() != null && !wrapper.getSaml2().getAuthnStatements().isEmpty()) {
                long authInstant = 
                    wrapper.getSaml2().getAuthnStatements().get(0).getAuthnInstant().getMillis();
                idToken.setAuthenticationTime(authInstant / 1000L);
            }
        } catch (WSSecurityException ex) {
            throw new OAuthServiceException("Error converting SAML token", ex);
        }
        
        // Map claims
        if (claims != null) {
            String firstName = null;
            String lastName = null;
            for (Claim c : claims) {
                if (!(c.getValue() instanceof String)) {
                    continue;
                }
                if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                    idToken.setGivenName((String)c.getValue());
                    firstName = (String)c.getValue();
                } else if (ClaimTypes.LASTNAME.equals(c.getClaimType())) {
                    idToken.setFamilyName((String)c.getValue());
                    lastName = (String)c.getValue();
                } else if (ClaimTypes.EMAILADDRESS.equals(c.getClaimType())) {
                    idToken.setEmail((String)c.getValue());
                } else if (ClaimTypes.DATEOFBIRTH.equals(c.getClaimType())) {
                    idToken.setBirthDate((String)c.getValue());
                } else if (ClaimTypes.HOMEPHONE.equals(c.getClaimType())) {
                    idToken.setPhoneNumber((String)c.getValue());
                } else if (ClaimTypes.GENDER.equals(c.getClaimType())) {
                    idToken.setGender((String)c.getValue());
                } else if (ClaimTypes.WEB_PAGE.equals(c.getClaimType())) {
                    idToken.setWebsite((String)c.getValue());
                }
            }
            
            if (firstName != null && lastName != null) {
                idToken.setName(firstName + " " + lastName);
            }
        }
        
        if (nonce != null) {
            idToken.setNonce(nonce);
        }
        
        return idToken;
    }

}
