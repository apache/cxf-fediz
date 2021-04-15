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
package org.apache.cxf.fediz.spring.web;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.FederationConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;

public class FederationSignOutCleanupFilter extends GenericFilterBean {

    private static final Logger LOG = LoggerFactory.getLogger(FederationSignOutCleanupFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        String wa = request.getParameter(FederationConstants.PARAM_ACTION);
        if (FederationConstants.ACTION_SIGNOUT_CLEANUP.equals(wa)) {
            if (request instanceof HttpServletRequest) {
                ((HttpServletRequest)request).getSession().invalidate();
            }

            final ServletOutputStream responseOutputStream = response.getOutputStream();
            InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("logout.jpg");
            if (inputStream == null) {
                LOG.warn("Could not write logout.jpg");
                return;
            }
            int read;
            byte[] buf = new byte[1024];
            while ((read = inputStream.read(buf)) != -1) {
                responseOutputStream.write(buf, 0, read);
            }
            inputStream.close();
            responseOutputStream.flush();
        } else {
            chain.doFilter(request, response);
        }
    }
}
