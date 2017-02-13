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

import javax.security.auth.Subject;

import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.RoleRunAsToken;
import org.eclipse.jetty.security.RunAsToken;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;


/**
 * Federation Identity Service implementation.
 * This service handles only role reference maps passed in an
 * associated {@link org.eclipse.jetty.server.UserIdentity.Scope}.  If there are roles
 * refs present, then associate will wrap the UserIdentity with one
 * that uses the role references in the
 * {@link org.eclipse.jetty.server.UserIdentity#isUserInRole(String, org.eclipse.jetty.server.UserIdentity.Scope)}
 * implementation. All other operations are effectively noops.
 *
 */
public class FederationIdentityService implements IdentityService {
    private static final Logger LOG = Log.getLogger(FederationIdentityService.class);

    public FederationIdentityService() {
    }


    /**
     * If there are roles refs present in the scope, then wrap the UserIdentity
     * with one that uses the role references in the
     * {@link UserIdentity#isUserInRole(String, org.eclipse.jetty.server.UserIdentity.Scope)}
     */
    public Object associate(UserIdentity user) {
        return null;
    }

    public void disassociate(Object previous) {
    }

    public Object setRunAs(UserIdentity user, RunAsToken token) {
        return token;
    }

    public void unsetRunAs(Object lastToken) {
    }

    public RunAsToken newRunAsToken(String runAsName) {
        return new RoleRunAsToken(runAsName);
    }

    public UserIdentity getSystemUserIdentity() {
        return null;
    }

    public UserIdentity newUserIdentity(
        final Subject subject, final Principal userPrincipal, final String[] roles) {

        try {
            FederationUserPrincipal fup = (FederationUserPrincipal)userPrincipal;
            return new FederationUserIdentity(subject, userPrincipal, roles, fup.getFedizResponse());
        } catch (ClassCastException ex) {
            LOG.warn("Principal must be instance of FederationUserPrincipal");
            throw new IllegalStateException("Principal must be instance of FederationUserPrincipal");
        }


    }

}
