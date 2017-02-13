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
import java.security.cert.Certificate;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.RequestState;

public class FedizRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String action;
    private String responseToken;
    private String freshness;
    private String state;
    private Certificate[] certs;
    private transient HttpServletRequest request;
    private RequestState requestState;

    public Certificate[] getCerts() {
        if (certs != null) {
            return Arrays.copyOf(certs, certs.length);
        }
        return null;
    }
    public void setCerts(Certificate[] certs) {
        if (certs != null) {
            this.certs = Arrays.copyOf(certs, certs.length);
        } else {
            this.certs = null;
        }
    }
    public String getResponseToken() {
        return responseToken;
    }
    public void setResponseToken(String responseToken) {
        this.responseToken = responseToken;
    }
    public String getAction() {
        return action;
    }
    public void setAction(String action) {
        this.action = action;
    }
    public String getFreshness() {
        return freshness;
    }
    public void setFreshness(String freshness) {
        this.freshness = freshness;
    }
    public String getState() {
        return state;
    }
    public void setState(String state) {
        this.state = state;
    }
    public HttpServletRequest getRequest() {
        return request;
    }
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }
    public RequestState getRequestState() {
        return requestState;
    }
    public void setRequestState(RequestState requestState) {
        this.requestState = requestState;
    }

}
