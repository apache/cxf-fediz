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
package org.apache.cxf.fediz.common;

import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.processor.ClaimsProcessor;

/**
 * Returns same list of claims as provided (no changes)
 *
 */
public class ClaimMutateProcessor implements ClaimsProcessor {

    @Override
    public List<Claim> processClaims(List<Claim> claims) {
        List<Claim> newClaimList = new ArrayList<>();

        for (Claim c : claims) {
            if (ClaimTypes.PRIVATE_PERSONAL_IDENTIFIER.equals(c.getClaimType())) {
                Claim lowerClaim = new Claim();
                lowerClaim.setClaimType(ClaimTypes.FIRSTNAME);
                lowerClaim.setValue(c.getValue().toString().toLowerCase());

                Claim upperClaim = new Claim();
                upperClaim.setClaimType(ClaimTypes.LASTNAME);
                upperClaim.setValue(c.getValue().toString().toUpperCase());

                newClaimList.add(lowerClaim);
                newClaimList.add(upperClaim);
            }
        }

        return newClaimList;
    }

}
