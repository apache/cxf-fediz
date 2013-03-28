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
package org.apache.cxf.fediz.service.idp.beans;

import java.util.StringTokenizer;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.service.idp.UsernamePasswordCredentials;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author fr17993 This class is responsible to decode authorization header with
 *         basic authentication.
 */

public class DecodeAuthorizationHeaderAction {

    public UsernamePasswordCredentials submit(RequestContext requestContext)
        throws Exception {
        String authorizationHeader = WebUtils.getHttpServletRequest(
                requestContext).getHeader("Authorization");
        String username = null;
        String password = null;

        StringTokenizer st = new StringTokenizer(authorizationHeader, " ");
        String authType = st.nextToken();
        String encoded = st.nextToken();

        if (!authType.equalsIgnoreCase("basic")) {
            throw new Exception("Invalid Authorization header");
        }

        String decoded = new String(Base64Utility.decode(encoded));

        int colon = decoded.indexOf(':');
        if (colon < 0) {
            username = decoded;
        } else {
            username = decoded.substring(0, colon);
            password = decoded.substring(colon + 1, decoded.length());
        }
        UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials();
        usernamePasswordCredentials.setUsername(username);
        usernamePasswordCredentials.setPassword(password);
        return usernamePasswordCredentials;
    }
}
