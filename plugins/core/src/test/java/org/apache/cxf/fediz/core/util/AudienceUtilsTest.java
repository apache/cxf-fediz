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

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests for the AudienceRestriction validation in AudienceUtils.
 */
public class AudienceUtilsTest {

    private static final String AUDIENCE = "urn:org:apache:cxf:fediz:fedizhelloworld";

    @Test
    public void testMatchingAudience() {
        Assertions.assertTrue(
            AudienceUtils.validateAudienceRestrictions(AUDIENCE, Collections.singletonList(AUDIENCE), null));
    }

    @Test
    public void testMatchingOneOfSeveralAudiences() {
        Assertions.assertTrue(AudienceUtils.validateAudienceRestrictions(AUDIENCE,
            List.of("urn:org:apache:cxf:fediz:other", AUDIENCE), "https://localhost/fedizhelloworld"));
    }

    @Test
    public void testNonMatchingAudience() {
        Assertions.assertFalse(AudienceUtils.validateAudienceRestrictions("urn:org:apache:cxf:fediz:other",
            Collections.singletonList(AUDIENCE), null));
    }

    @Test
    public void testMissingAudienceWithConfiguredAudiences() {
        Assertions.assertFalse(
            AudienceUtils.validateAudienceRestrictions(null, Collections.singletonList(AUDIENCE), null));
    }

    @Test
    public void testAudienceWithNoConfiguredAudiences() {
        Assertions.assertFalse(AudienceUtils.validateAudienceRestrictions(AUDIENCE, Collections.emptyList(), null));
    }

    @Test
    public void testNoAudienceAndNoConfiguredAudiences() {
        Assertions.assertTrue(AudienceUtils.validateAudienceRestrictions(null, Collections.emptyList(), null));
    }

}
