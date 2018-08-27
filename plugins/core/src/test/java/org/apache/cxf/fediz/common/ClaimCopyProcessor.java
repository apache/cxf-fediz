package org.apache.cxf.fediz.common;

import java.util.List;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.processor.ClaimsProcessor;

/**
 * Returns same list of claims as provided (no changes)
 *
 */
public class ClaimCopyProcessor implements ClaimsProcessor {

    @Override
    public List<Claim> processClaims(List<Claim> claims) {
        return claims;
    }

}
