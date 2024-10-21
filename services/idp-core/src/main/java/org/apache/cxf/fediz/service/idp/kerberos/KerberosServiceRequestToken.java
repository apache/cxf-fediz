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
package org.apache.cxf.fediz.service.idp.kerberos;

import java.util.Arrays;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Holds the Kerberos/SPNEGO token for requesting a kerberized service
 * and is also the output of <code>KerberosServiceAuthenticationProvider</code>.<br>
 * Will mostly be created in <code>SpnegoAuthenticationProcessingFilter</code>
 * and authenticated in <code>KerberosServiceAuthenticationProvider</code>.
 *
 * This token cannot be re-authenticated, as you will get a Kerberos Reply error.
 *
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 * @see KerberosServiceAuthenticationProvider
 * @see KerberosAuthenticationProcessingFilter
 */
public class KerberosServiceRequestToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 395488921064775014L;
    private final byte[] token;
    private final Object principal;

    /** Creates an authenticated token, normally used as an output of an authentication provider.
     * @param principal the user principal (mostly of instance <code>UserDetails</code>
     * @param authorities the authorities which are granted to the user
     * @param token the Kerberos/SPNEGO token
     * @see UserDetails
     */
    public KerberosServiceRequestToken(Object principal,
                                       Collection<? extends GrantedAuthority> authorities,
                                       byte[] token) {
        super(authorities);
        if (token != null) {
            this.token = Arrays.copyOf(token, token.length);
        } else {
            this.token = null;
        }
        this.principal = principal;
        super.setAuthenticated(true);
    }

    /**
     * Creates an unauthenticated instance which should then be authenticated by
     * <code>KerberosServiceAuthenticationProvider/code>
     *
     * @param token Kerberos/SPNEGO token
     * @see KerberosServiceAuthenticationProvider
     */
    public KerberosServiceRequestToken(byte[] token) {
        super(null);
        if (token != null) {
            this.token = Arrays.copyOf(token, token.length);
        } else {
            this.token = null;
        }
        this.principal = null;
    }

    /**
     * Calculates hashcode based on the Kerberos token
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(token);
        return result;
    }

    /**
     * equals() is based only on the Kerberos token
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        KerberosServiceRequestToken other = (KerberosServiceRequestToken) obj;
        return Arrays.equals(token, other.token);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.core.Authentication#getCredentials()
     */
    public Object getCredentials() {
        return null;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.core.Authentication#getPrincipal()
     */
    public Object getPrincipal() {
        return this.principal;
    }

    /** Returns the Kerberos token
     */
    public byte[] getToken() {
        if (token != null) {
            return Arrays.copyOf(token, token.length);
        }
        return null;
    }
}
