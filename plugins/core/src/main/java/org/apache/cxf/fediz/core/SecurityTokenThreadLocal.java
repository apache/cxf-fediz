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

package org.apache.cxf.fediz.core;

import org.w3c.dom.Element;


/**
 * Thread local storage for security token
 */
public final class SecurityTokenThreadLocal {

    private static final ThreadLocal<Element> TLS = 
        new ThreadLocal<Element>();

    private SecurityTokenThreadLocal() {
    }    
        
    public static void setToken(Element token) {
        if (token == null) { 
            TLS.remove();
        } else {
            TLS.set(token);
        }
    }

    public static Element getToken() {
        return TLS.get();
    }
    

}
