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

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RequestState implements Serializable {

    private static final long serialVersionUID = 869323136115571943L;

    private String targetAddress;
    private String idpServiceAddress;
    private String requestId;
    private String issuerId;
    private String webAppContext;
    private long createdAt;
    private String state;
    private String webAppDomain;

    public RequestState() {

    }

    // CHECKSTYLE:OFF
    public RequestState(String targetAddress,
                        String idpServiceAddress,
                        String requestId,
                        String issuerId,
                        String webAppContext,
                        String webAppDomain,
                        String state,
                        long createdAt) {
        setTargetAddress(targetAddress);
        setIdpServiceAddress(idpServiceAddress);
        setRequestId(requestId);
        setIssuerId(issuerId);
        setWebAppContext(webAppContext);
        setWebAppDomain(webAppDomain);
        setState(state);
        setCreatedAt(createdAt);
    }


    public void setTargetAddress(String targetAddress) {
        this.targetAddress = targetAddress;
    }

    public void setIdpServiceAddress(String idpServiceAddress) {
        this.idpServiceAddress = idpServiceAddress;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public void setWebAppContext(String webAppContext) {
        this.webAppContext = webAppContext;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getTargetAddress() {
        return targetAddress;
    }

    public String getIdpServiceAddress() {
        return idpServiceAddress;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getIssuerId() {
        return issuerId;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public String getWebAppContext() {
        return webAppContext;
    }

    public String getState() {
        return state;
    }

    public String getWebAppDomain() {
        return webAppDomain;
    }

    public void setWebAppDomain(String webAppDomain) {
        this.webAppDomain = webAppDomain;
    }

}
