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
package org.apache.cxf.fediz.service.sts;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.cxf.sts.claims.Claim;
import org.apache.cxf.sts.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.RequestClaim;
import org.apache.cxf.sts.claims.RequestClaimCollection;

/**
 * A custom ClaimsHandler implementation for use in the tests.
 */
public class FileClaimsHandler implements ClaimsHandler {

    public static final URI ROLE = 
        URI.create("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role");

    private Map<String, Map<String, String>> userClaims;
    private List<URI> supportedClaims;

    public void setUserClaims(Map<String, Map<String, String>> userClaims) {
        this.userClaims = userClaims;
    }

    public Map<String, Map<String, String>> getUserClaims() {
        return userClaims;
    }
    
    public void setSupportedClaims(List<URI> supportedClaims) {
        this.supportedClaims = supportedClaims;
    }
    
    @Override
    public List<URI> getSupportedClaimTypes() {
        return Collections.unmodifiableList(this.supportedClaims);
    }
    

    @Override
    public ClaimCollection retrieveClaimValues(RequestClaimCollection claims,
            ClaimsParameters parameters) {

        if (getUserClaims() == null) {
            return new ClaimCollection();
        }

        if (claims == null || claims.size() == 0) {
            return new ClaimCollection();
        }

        Map<String, String> claimMap = getUserClaims().get(parameters.getPrincipal().getName());
        if (claimMap == null || claimMap.size() == 0) {
            return new ClaimCollection();
        }

        if (claims != null && claims.size() > 0) {
            ClaimCollection claimCollection = new ClaimCollection();
            for (RequestClaim requestClaim : claims) { 
                String claimValue = claimMap.get(requestClaim.getClaimType().toString());
                if (claimValue != null) {
                    Claim claim = new Claim();
                    claim.setClaimType(requestClaim.getClaimType());
                    claim.setIssuer("Test Issuer");
                    claim.setOriginalIssuer("Original Issuer");
                    claim.addValue(claimValue);
                    claimCollection.add(claim);
                }   
            }
            return claimCollection;
        }
        return null;

    }



}
