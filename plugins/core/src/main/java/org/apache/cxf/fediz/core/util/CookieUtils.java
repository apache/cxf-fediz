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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Some Utility methods for manipulating cookies
 */
public final class CookieUtils  {
    
    private CookieUtils() {
        // complete
    }

    public static String createCookie(String name, 
                                  String value, 
                                  String path,
                                  String domain,
                                  long stateTimeToLive) { 
        
        String contextCookie = name + "=" + value;
        // Setting a specific path restricts the browsers
        // to return a cookie only to the web applications
        // listening on that specific context path
        if (path != null) {
            contextCookie += ";Path=" + path;
        }
        
        // Setting a specific domain further restricts the browsers
        // to return a cookie only to the web applications
        // listening on the specific context path within a particular domain
        if (domain != null) {
            contextCookie += ";Domain=" + domain;
        }
        
        // Keep the cookie across the browser restarts until it actually expires.
        // Note that the Expires property has been deprecated but apparently is 
        // supported better than 'max-age' property by different browsers 
        // (Firefox, IE, etc)
        Date expiresDate = new Date(System.currentTimeMillis() + stateTimeToLive);
        String cookieExpires = getHttpDateFormat().format(expiresDate);
        contextCookie += ";Expires=" + cookieExpires;
        
        return contextCookie;
    }
    
    public static SimpleDateFormat getHttpDateFormat() {
        SimpleDateFormat dateFormat =
            new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        TimeZone tZone = TimeZone.getTimeZone("GMT");
        dateFormat.setTimeZone(tZone);
        return dateFormat;
    }
    
    public static boolean isStateExpired(long stateCreatedAt, boolean detectExpiredTokens,
                                         long expiresAt, long stateTTL) {
        Date currentTime = new Date();
        if (currentTime.after(new Date(stateCreatedAt + stateTTL))) {
            return true;
        }
        
        return detectExpiredTokens && expiresAt > 0 && currentTime.after(new Date(expiresAt));
    }
    
}
