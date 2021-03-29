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
package org.apache.cxf.fediz.cxf.plugin.state;

import org.apache.cxf.fediz.core.RequestState;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class EHCacheSPStateManagerTest {

    private static final int HEAP_ENTRIES = 5000;

    private static SPStateManager stateManager;

    @Test
    public void testRequestState() {
        RequestState requestState = new RequestState();
        for (int i = 0; i < 2 * HEAP_ENTRIES; ++i) {
            stateManager.setRequestState(String.valueOf(i), requestState);
        }
        for (int i = 0; i < 2 * HEAP_ENTRIES; ++i) {
            assertNotNull(String.valueOf(i), stateManager.removeRequestState(String.valueOf(i)));
            assertNull(stateManager.removeRequestState(String.valueOf(i)));
        }
    }

    @Test
    public void testResponseState() {
        assertNull(stateManager.getResponseState(""));
        ResponseState responseState = new ResponseState();
        for (int i = 0; i < 2 * HEAP_ENTRIES; ++i) {
            stateManager.setResponseState(String.valueOf(i), responseState);
        }
        for (int i = 0; i < 2 * HEAP_ENTRIES; ++i) {
            assertNotNull(String.valueOf(i), stateManager.getResponseState(String.valueOf(i)));
            assertNotNull(String.valueOf(i), stateManager.removeResponseState(String.valueOf(i)));
            assertNull(stateManager.removeResponseState(String.valueOf(i)));
        }
    }

    @Test
    public void testTwoManagers() throws Exception {
        try (SPStateManager stateManager = new EHCacheSPStateManager("fediz-ehcache.xml")) {
            assertNotNull(stateManager);
        }
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        stateManager = new EHCacheSPStateManager("fediz-ehcache.xml");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        stateManager.close();
    }
}
