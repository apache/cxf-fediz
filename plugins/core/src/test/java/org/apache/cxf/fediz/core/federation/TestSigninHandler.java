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

package org.apache.cxf.fediz.core.federation;

import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.handler.SigninHandler;
import org.apache.cxf.fediz.core.processor.FedizResponse;

public class TestSigninHandler extends SigninHandler<FedizPrincipal> {
        
    public TestSigninHandler(FedizContext fedizContext) {
        super(fedizContext);
    }

    @Override
    protected FedizPrincipal createPrincipal(HttpServletRequest request, HttpServletResponse response,
        FedizResponse wfRes) {

        List<String> roles = wfRes.getRoles();
        if (roles == null || roles.size() == 0) {
            roles = Collections.singletonList("Authenticated");
        }

        // proceed creating the JAAS Subject
        FedizPrincipal principal = new FederationPrincipalImpl(wfRes.getUsername(), roles,
                                                               wfRes.getClaims(), wfRes.getToken());

        return principal;
    }
    
    private static class FederationPrincipalImpl implements FedizPrincipal {

        protected ClaimCollection claims;
        protected Element loginToken;
        private String username;
        
        FederationPrincipalImpl(String username, List<String> roles,
                List<Claim> claims, Element loginToken) {
            this.claims = new ClaimCollection(claims);
            this.loginToken = loginToken;
            this.username = username;
        }
        
        public ClaimCollection getClaims() {
            return this.claims;
        }
        
        @Override
        public Element getLoginToken() {
            return loginToken;
        }

        @Override
        public String getName() {
            return username;
        }

    }

}
