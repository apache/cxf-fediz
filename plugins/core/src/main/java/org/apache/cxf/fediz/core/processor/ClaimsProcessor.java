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

import java.util.List;

import org.apache.cxf.fediz.core.Claim;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface ClaimsProcessor {

    /**
     * This operation can be used to transform, filter or trigger other actions
     * based on the input claims. The response can be the same list of claims as
     * from the input parameter, a subset of it or a renamed or extended list of
     * claims.
     * 
     * @param claims Claims to be processed
     * @return List of processed claims
     */
    List<Claim> processClaims(List<Claim> claims);

}
