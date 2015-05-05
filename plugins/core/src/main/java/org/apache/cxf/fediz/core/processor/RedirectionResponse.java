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

package org.apache.cxf.fediz.core.processor;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.fediz.core.RequestState;

/**
 * Some parameters to redirect to a token issuer (either SignIn or SignOut)
 */
public class RedirectionResponse implements Serializable {

    private static final long serialVersionUID = 3182350165552249151L;
    
    private String redirectionURL;
    private Map<String, String> headers = new HashMap<>();
    private RequestState requestState;
    
    public String getRedirectionURL() {
        return redirectionURL;
    }
    
    public void setRedirectionURL(String redirectionURL) {
        this.redirectionURL = redirectionURL;
    }
    
    public Map<String, String> getHeaders() {
        return headers;
    }
    
    public void addHeader(String headerName, String headerValue) {
        headers.put(headerName, headerValue);
    }

    public RequestState getRequestState() {
        return requestState;
    }

    public void setRequestState(RequestState requestState) {
        this.requestState = requestState;
    }

}
