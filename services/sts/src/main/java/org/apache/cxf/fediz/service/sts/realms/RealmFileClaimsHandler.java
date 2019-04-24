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
package org.apache.cxf.fediz.service.sts.realms;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.rt.security.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;

/**
 * A custom ClaimsHandler implementation for use with "userClaims.xml"
 */
public class RealmFileClaimsHandler implements ClaimsHandler {

    private static final Logger LOG = LogUtils.getL7dLogger(RealmFileClaimsHandler.class);

    private Map<String, Map<String, String>> userClaims;
    private List<String> supportedClaims;
    private String realm;

    public void setUserClaims(Map<String, Map<String, String>> userClaims) {
        this.userClaims = userClaims;
    }

    public Map<String, Map<String, String>> getUserClaims() {
        return userClaims;
    }

    public void setSupportedClaims(List<String> supportedClaims) {
        this.supportedClaims = supportedClaims;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getRealm() {
        return realm;
    }

    @Override
    public List<String> getSupportedClaimTypes() {
        return Collections.unmodifiableList(this.supportedClaims);
    }


    @Override
    public ProcessedClaimCollection retrieveClaimValues(ClaimCollection claims,
            ClaimsParameters parameters) {

        if (parameters.getRealm() == null || !parameters.getRealm().equalsIgnoreCase(getRealm())) {
            LOG.fine("Realm '" + parameters.getRealm() + "' doesn't match with configured realm '" + getRealm() + "'");
            return new ProcessedClaimCollection();
        }
        if (getUserClaims() == null || parameters.getPrincipal() == null) {
            return new ProcessedClaimCollection();
        }

        if (claims == null || claims.isEmpty()) {
            LOG.fine("No claims requested");
            return new ProcessedClaimCollection();
        }

        Map<String, String> claimMap = getUserClaims().get(parameters.getPrincipal().getName());
        if (claimMap == null || claimMap.isEmpty()) {
            LOG.fine("Claims requested for principal '" + parameters.getPrincipal().getName()
                     + "' but not found");
            return new ProcessedClaimCollection();
        }
        LOG.fine("Claims found for principal '" + parameters.getPrincipal().getName() + "'");

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
