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

package org.apache.cxf.fediz.spring.authentication;

import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.BadCredentialsException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests for the AudienceRestriction validation in the FederationAuthenticationProvider.
 */
public class FederationAuthenticationProviderAudienceTest {

    private static final String AUDIENCE = "urn:org:apache:cxf:fediz:fedizhelloworld";

    private final FederationAuthenticationProvider provider = new FederationAuthenticationProvider();

    @Test
    public void testMatchingAudience() {
        provider.validateAudienceRestriction(AUDIENCE, Collections.singletonList(AUDIENCE));
    }

    @Test
    public void testMatchingOneOfSeveralAudiences() {
        provider.validateAudienceRestriction(AUDIENCE, List.of("urn:org:apache:cxf:fediz:other", AUDIENCE));
    }

    @Test
    public void testNonMatchingAudience() {
        Assertions.assertThrows(BadCredentialsException.class, () ->
            provider.validateAudienceRestriction("urn:org:apache:cxf:fediz:other",
                Collections.singletonList(AUDIENCE)));
    }

    @Test
    public void testMissingAudienceWithConfiguredAudiences() {
        Assertions.assertThrows(BadCredentialsException.class, () ->
            provider.validateAudienceRestriction(null, Collections.singletonList(AUDIENCE)));
    }

    @Test
    public void testAudienceWithNoConfiguredAudiences() {
        Assertions.assertThrows(BadCredentialsException.class, () ->
            provider.validateAudienceRestriction(AUDIENCE, Collections.emptyList()));
    }

    @Test
    public void testNoAudienceAndNoConfiguredAudiences() {
        provider.validateAudienceRestriction(null, Collections.emptyList());
    }

}
