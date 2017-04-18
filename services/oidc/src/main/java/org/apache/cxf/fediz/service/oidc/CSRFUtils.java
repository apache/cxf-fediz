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
package org.apache.cxf.fediz.service.oidc;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.rt.security.crypto.CryptoUtils;

public final class CSRFUtils {

    public static final String CSRF_TOKEN = "CSRF_TOKEN";

    private CSRFUtils() {
        // complete
    }

    public static String getCSRFToken(HttpServletRequest request, boolean create) {
        if (request != null && request.getSession() != null) {
            // Return an existing token first
            String savedToken = (String)request.getSession().getAttribute(CSRF_TOKEN);
            if (savedToken != null) {
                return savedToken;
            }

            // If no existing token then create a new one, save it, and return it
            if (create) {
                String token = StringUtils.toHexString(CryptoUtils.generateSecureRandomBytes(16));
                request.getSession().setAttribute(CSRF_TOKEN, token);
                return token;
            }
        }

        return null;
    }
}
