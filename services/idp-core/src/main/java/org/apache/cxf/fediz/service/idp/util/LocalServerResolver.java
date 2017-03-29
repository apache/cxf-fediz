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
package org.apache.cxf.fediz.service.idp.util;

import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.execution.RequestContext;

/**
 * Detects if a given URL means the local server (useful in case IDP/STS are co-located). If port 0 is
 * explicitly set, then {@link #resolve(String, RequestContext)} will replace the original URL with a url
 * containing the local server port.
 */
public final class LocalServerResolver {

    private static final Logger LOG = LoggerFactory.getLogger(LocalServerResolver.class);

    private LocalServerResolver() {
    }

    /**
     * If url contains a 0 port, replaces it with the local server port. Otherwise returns url as-is (no
     * modification).
     */
    public static String resolve(String url) {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (!(requestAttributes instanceof ServletRequestAttributes)) {
            return url;
        }
        return resolve(url, ((ServletRequestAttributes)requestAttributes).getRequest());
    }

    public static String resolve(String url, RequestContext context) {
        if (context == null) {
            return url;
        }
        return resolve(url, WebUtils.getHttpServletRequest(context));
    }

    public static String resolve(String url, HttpServletRequest request) {
        if (request == null) {
            return url;
        }
        if (isLocal(url)) {
            try {
                URL urlValue = new URL(url);
                URL updatedUrl = new URL(urlValue.getProtocol(), urlValue.getHost(), request.getLocalPort(),
                                         urlValue.getFile());
                LOG.debug("URL updated to {}", updatedUrl.toString());
                return updatedUrl.toString();
            } catch (MalformedURLException e) {
                LOG.error("Invalid Url '{}': {}", url, e.getMessage());
            }
        }
        return url;
    }

    /**
     * Returns true if the url represents a local server (that is port is explicitly set to 0)
     */
    public static boolean isLocal(String url) {
        boolean isLocal = false;
        try {
            URL urlValue = new URL(url);
            isLocal = urlValue.getPort() == 0;
            if (isLocal) {
                LOG.info("Port is 0 used for {}. Local server port will be used.", url);
            }
        } catch (MalformedURLException e) {
            LOG.error("Invalid Url '" + url + "': " + e.getMessage());
        }
        return isLocal;
    }
}
