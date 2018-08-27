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
