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
package org.apache.cxf.fediz.service.idp;

import java.io.IOException;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.common.util.Base64Utility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicAuthenticationFilter extends AbstractAuthFilter {

    public static final String AUTH_HEADER_NAME = "WWW-Authenticate";

    private static final Logger LOG = LoggerFactory.getLogger(BasicAuthenticationFilter.class);
    
//    static {
//        LOG = LoggerFactory.getLogger(BasicAuthenticationFilter.class);
//    }

    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException {

        String auth = request.getHeader("Authorization");
        LOG.debug("Authorization header: " + auth);

        if (auth == null) {
            // request authentication from browser
            StringBuilder value = new StringBuilder(16);
            value.append("Basic realm=\"IDP\"");
            response.setHeader(AUTH_HEADER_NAME, value.toString());
            response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            this.setNextState(States.USERNAME_PASSWORD_REQUIRED.toString(), context);
            // signal to send response to client or throw exception
            // SEND_RESPONSE, CONTINUE
            context.put(AbstractAuthFilter.PROCESSING_STATE, AbstractAuthFilter.ProcessingState.SEND_RESPONSE);
            return;

        } else {
            String username = null;
            String password = null;

            try {
                StringTokenizer st = new StringTokenizer(auth, " ");
                String authType = st.nextToken();
                String encoded = st.nextToken();

                if (!authType.equalsIgnoreCase("basic")) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Authorization header");
                    return;
                }

                String decoded = new String(
                                            Base64Utility.decode(encoded));

                int colon = decoded.indexOf(':');
                if (colon < 0) {
                    username = decoded;
                } else {
                    username = decoded.substring(0, colon);
                    password = decoded.substring(colon + 1,
                                                 decoded.length());
                }
                context.put(AuthContext.AUTH_USERNAME, username);
                context.put(AuthContext.AUTH_PASSWORD, password);

            } catch (Exception ex) {
                LOG.error("Invalid Authorization header", ex);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid Authorization header");
                throw new ProcessingException("Invalid Authorization header");
            }
        }
    }

}
