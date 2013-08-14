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

import javax.servlet.http.Cookie;

import org.apache.cxf.fediz.service.idp.util.WebUtils;
//import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author fr17993 
 */

public class HomeRealmReminder {

    public static final String FEDIZ_HOME_REALM = "FEDIZ_HOME_REALM";


//    public boolean alreadyAuthenticated() {
//        return SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
//    }

    public Cookie readCookie(RequestContext requestContext) {
        return WebUtils.readCookie(requestContext, FEDIZ_HOME_REALM);
    }

    public void addCookie(RequestContext requestContext, String cookieValue) {
        WebUtils.addCookie(requestContext, FEDIZ_HOME_REALM, cookieValue);
    }

    public void removeCookie(RequestContext requestContext) {
        WebUtils.removeCookie(requestContext, FEDIZ_HOME_REALM);
    }
}
