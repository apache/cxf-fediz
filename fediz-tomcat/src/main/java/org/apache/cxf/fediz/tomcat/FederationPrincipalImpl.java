package org.apache.cxf.fediz.tomcat;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FederationPrincipal;

public class FederationPrincipalImpl extends GenericPrincipal implements FederationPrincipal {

    protected ClaimCollection claims;

    public FederationPrincipalImpl(String username, List<String> roles,
            List<Claim> claims) {
        super(username, null, roles);
        this.claims = new ClaimCollection(claims);
    }

    public ClaimCollection getClaims() {
        return this.claims;
    }

}
