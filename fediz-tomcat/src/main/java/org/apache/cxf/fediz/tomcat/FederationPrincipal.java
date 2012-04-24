package org.apache.cxf.fediz.tomcat;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;

public class FederationPrincipal extends GenericPrincipal {
    // [TODO] make sure claims and roles are imutable 
    protected ClaimCollection claims;

    public FederationPrincipal(String username, List<String> roles, List<Claim> claims) {
        super(username, null, roles);
        this.claims = new ClaimCollection(claims);
    }

    public ClaimCollection getClaims() {
        return this.claims;
    }



}
