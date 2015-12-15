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
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;


public class SamlTokenConverter {

    private String issuer;
    private long defaultTimeToLive = 3600L;
    
    public IdToken convertToIdToken(Element samlToken, 
                                    String subjectName, 
                                    ClaimCollection claims,
                                    String clientId) {
        // The current SAML Assertion represents an authentication record.
        // It has to be translated into IdToken (JWT) so that it can be returned 
        // to client applications participating in various OIDC flows.
        
        IdToken idToken = new IdToken();
        // Subject name is provided by FedizPrincipal which is initialized from the current SAML token 
        idToken.setSubject(subjectName);
        // SAML assertion audiences might be added if needed given that JWT can hold an array of audiences
        idToken.setAudience(clientId);
        
        Assertion saml2Assertion = getSaml2Assertion(samlToken);
        if (saml2Assertion != null) {
            // Issuer
            Issuer assertionIssuer = saml2Assertion.getIssuer();
            if (assertionIssuer != null) {
                idToken.setIssuer(assertionIssuer.getValue());
            }
            // issueInstant
            DateTime issueInstant = saml2Assertion.getIssueInstant();
            if (issueInstant != null) {
                idToken.setIssuedAt(issueInstant.getMillis() / 1000);
            }
            
            // expiryTime
            if (saml2Assertion.getConditions() != null) {
                DateTime expires = saml2Assertion.getConditions().getNotOnOrAfter();
                if (expires != null) {
                    idToken.setExpiryTime(expires.getMillis() / 1000);
                }
            }
            
            // authInstant
            if (!saml2Assertion.getAuthnStatements().isEmpty()) {
                DateTime authInstant = 
                    saml2Assertion.getAuthnStatements().get(0).getAuthnInstant();
                idToken.setAuthenticationTime(authInstant.getMillis() / 1000L);
            }
        }
        // Check if default issuer, issuedAt and expiryTime values have to be set 
        if (issuer != null) {
            idToken.setIssuer(issuer);
        } else if (saml2Assertion != null) {
            Issuer assertionIssuer = saml2Assertion.getIssuer();
            if (assertionIssuer != null) {
                idToken.setIssuer(assertionIssuer.getValue());
            }
        }
        
        long currentTimeInSecs = System.currentTimeMillis() / 1000;
        if (idToken.getIssuedAt() == null) {
            idToken.setIssuedAt(currentTimeInSecs);
        }
        if (idToken.getExpiryTime() == null) {
            idToken.setExpiryTime(currentTimeInSecs + defaultTimeToLive);
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
        
        return idToken;
    }

    
    private Assertion getSaml2Assertion(Element samlToken) {
        // Should a null assertion lead to the exception ?
        try {
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(samlToken);
            return wrapper.getSaml2();
        } catch (WSSecurityException ex) {
            throw new OAuthServiceException("Error converting SAML token", ex);
        }
        
    }


    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }


    public void setDefaultTimeToLive(long defaultTimeToLive) {
        this.defaultTimeToLive = defaultTimeToLive;
    }

}
