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

package org.apache.cxf.fediz.jetty9;


import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;

import javax.security.auth.Subject;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.eclipse.jetty.server.UserIdentity;

public class FederationUserIdentity implements UserIdentity {

    private Subject subject;
    private Principal principal;
    private String[] roles;
    private FedizResponse fedResponse;

    public FederationUserIdentity(Subject subject, Principal principal,
                                  String[] roles, FedizResponse fedResponse) {
        this.subject = subject;
        this.principal = principal;
        if (roles != null) {
            this.roles = Arrays.copyOf(roles, roles.length);
        }
        this.fedResponse = fedResponse;
    }


    public Subject getSubject() {
        return subject;
    }

    public Principal getUserPrincipal() {
        return principal;
    }

    public boolean isUserInRole(String role, Scope scope) {
        if (scope != null && scope.getRoleRefMap() != null) {
            role = scope.getRoleRefMap().get(role);
        }

        if (this.roles != null) {
            for (String r : this.roles) {
                if (r.equals(role)) {
                    return true;
                }
            }
        }
        return false;
    }

    public Instant getExpiryDate() {
        return fedResponse.getTokenExpires();
    }

    public String getIssuer() {
        return fedResponse.getIssuer();
    }

    public String getAudience() {
        return fedResponse.getAudience();
    }

    public String getId() {
        return fedResponse.getUniqueTokenId();
    }

    public Element getToken() {
        return fedResponse.getToken();
    }

}
