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
import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

public class STSPortFilter extends GenericFilterBean implements ApplicationContextAware {

    private static final Logger LOG = LoggerFactory.getLogger(STSPortFilter.class);

    private ApplicationContext applicationContext;
    private STSAuthenticationProvider authenticationProvider;

    private boolean isPortSet;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        Assert.isTrue(applicationContext != null, "Application context must not be null");
        STSAuthenticationProvider authProvider = authenticationProvider;
        if (authProvider == null) {
            authProvider = applicationContext.getBean(STSAuthenticationProvider.class);
        }
        Assert.isTrue(authProvider != null, "STSAuthenticationProvider must be configured");

        //Only update the port if HTTPS is used, otherwise ignored (like retrieving the WADL over HTTP)
        if (!isPortSet && request.isSecure()) {
            try {
                URL url = new URL(authProvider.getWsdlLocation());
                if (url.getPort() == 0) {
                    URL updatedUrl = new URL(url.getProtocol(), url.getHost(), request.getLocalPort(), url.getFile());
                    setSTSWsdlUrl(authProvider, updatedUrl.toString());
                    LOG.info("STSAuthenticationProvider.wsdlLocation set to " + updatedUrl.toString());
                } else {
                    setSTSWsdlUrl(authProvider, url.toString());
                }
            } catch (MalformedURLException e) {
                LOG.error("Invalid Url '" + authProvider.getWsdlLocation() + "': "  + e.getMessage());
            }
        }

        chain.doFilter(request, response);
    }

    private synchronized void setSTSWsdlUrl(STSAuthenticationProvider authProvider, String wsdlUrl) {
        authProvider.setWsdlLocation(wsdlUrl);
        this.isPortSet = true;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public STSAuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

    public void setAuthenticationProvider(STSAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

}
