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

package org.apache.cxf.fediz.core.util;

import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;

/**
 * Few simple utils. This is originally from the CXF project.
 */
public final class StringUtils {

    private StringUtils() {
    }

    public static boolean isEmpty(String str) {
        if (str != null) {
            int len = str.length();
            for (int x = 0; x < len; ++x) {
                if (str.charAt(x) > ' ') {
                    return false;
                }
            }
        }
        return true;
    }

    public static String extractFullContextPath(HttpServletRequest request) throws MalformedURLException {
        String result;
        String contextPath = request.getContextPath();
        String requestUrl = request.getRequestURL().toString();
        String requestPath = new URL(requestUrl).getPath();
        // Cut request path of request url and add context path if not ROOT
        if (requestPath != null && !requestPath.isEmpty()) {
            int lastIndex = requestUrl.lastIndexOf(requestPath);
            result = requestUrl.substring(0, lastIndex);
        } else {
            result = requestUrl;
        }
        if (contextPath != null && !contextPath.isEmpty()) {
            // contextPath contains starting slash
            result = result + contextPath + '/';
        } else {
            result = result + '/';
        }
        return result;
    }
}
