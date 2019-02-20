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

import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.rt.security.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;

/**
 * A custom ClaimsHandler implementation for use in the tests.
 */
public class FileClaimsHandler implements ClaimsHandler {

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
    public ProcessedClaimCollection retrieveClaimValues(ClaimCollection claims,
            ClaimsParameters parameters) {

        if (getUserClaims() == null || parameters.getPrincipal() == null) {
            return new ProcessedClaimCollection();
        }

        if (claims == null || claims.isEmpty()) {
            return new ProcessedClaimCollection();
        }

        Map<String, String> claimMap = getUserClaims().get(parameters.getPrincipal().getName());
        if (claimMap == null || claimMap.isEmpty()) {
            return new ProcessedClaimCollection();
        }

        if (!claims.isEmpty()) {
            ProcessedClaimCollection claimCollection = new ProcessedClaimCollection();
            for (Claim requestClaim : claims) {
                String claimValue = claimMap.get(requestClaim.getClaimType().toString());
                if (claimValue != null) {
                    ProcessedClaim claim = new ProcessedClaim();
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
