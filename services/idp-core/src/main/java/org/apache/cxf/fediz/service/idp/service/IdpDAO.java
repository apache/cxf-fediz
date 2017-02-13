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

package org.apache.cxf.fediz.service.idp.service;

import java.util.List;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;

public interface IdpDAO {

    List<Idp> getIdps(int start, int size, List<String> expand);

    Idp getIdp(String realm, List<String> expand);

    Idp addIdp(Idp idp);

    void updateIdp(String realm, Idp idp);

    void deleteIdp(String realm);

    void addApplicationToIdp(Idp idp, Application application);

    void removeApplicationFromIdp(Idp idp, Application application);

    void addTrustedIdpToIdp(Idp idp, TrustedIdp trustedIdp);

    void removeTrustedIdpFromIdp(Idp idp, TrustedIdp trustedIdp);

    void addClaimToIdp(Idp idp, Claim claim);

    void removeClaimFromIdp(Idp idp, Claim claim);

}
