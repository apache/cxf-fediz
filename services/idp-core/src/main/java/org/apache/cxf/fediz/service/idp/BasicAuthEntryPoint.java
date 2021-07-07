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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;


/**
 * The entry point for BasicAuthentication. If the exception thrown is an AuthenticationServiceException, which
 * is thrown if the URL for the STS is incorrect for example, it returns 500. Otherwise 401.
 */
@Component
public class BasicAuthEntryPoint extends BasicAuthenticationEntryPoint {

    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException ex) throws IOException {
        if (ex instanceof AuthenticationServiceException) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.flushBuffer();
        } else {
            super.commence(request, response, ex);
        }
    }

    @Override
    public void afterPropertiesSet() {
        setRealmName("Fediz");
        super.afterPropertiesSet();
    }

}
