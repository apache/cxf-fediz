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

package org.apache.cxf.fediz.core.federation;

import org.w3c.dom.Element;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.TokenValidatorRequest;
import org.apache.cxf.fediz.core.TokenValidatorResponse;
import org.apache.cxf.fediz.core.config.FedizContext;


public class CustomValidator implements TokenValidator {

    @Override
    public boolean canHandleTokenType(String tokenType) {
        return true;
    }

    @Override
    public boolean canHandleToken(Element token) {
        return true;
    }

    @Override
    public TokenValidatorResponse validateAndProcessToken(
        TokenValidatorRequest request,
        FedizContext config
    ) {
        return new TokenValidatorResponse(null,
                                          FederationResponseTest.TEST_USER,
                                          FederationResponseTest.TEST_RSTR_ISSUER,
                                          null,
                                          FederationResponseTest.TEST_AUDIENCE);
    }

}
