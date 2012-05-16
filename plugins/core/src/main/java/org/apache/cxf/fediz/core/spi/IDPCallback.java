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

package org.apache.cxf.fediz.core.spi;

import java.net.URL;

import javax.servlet.http.HttpServletRequest;

public class IDPCallback extends AbstractServletCallback {

    private URL issuerUrl;
    private String trustedIssuer;

    public IDPCallback(HttpServletRequest request) {
        super(request);
    }

    /*public IDPCallback(HttpServletRequest request, URL issuerUrl,
            String trustedIssuer) {
        this(request);
        this.issuerUrl = issuerUrl;
        this.trustedIssuer = trustedIssuer;
    }*/

    public URL getIssuerUrl() {
        return issuerUrl;
    }

    public void setIssuerUrl(URL issuerUrl) {
        this.issuerUrl = issuerUrl;
    }

    public String getTrustedIssuer() {
        return trustedIssuer;
    }

    public void setTrustedIssuer(String trustedIssuer) {
        this.trustedIssuer = trustedIssuer;
    }

}
