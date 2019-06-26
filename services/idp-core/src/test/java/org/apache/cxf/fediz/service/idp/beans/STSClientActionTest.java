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
package org.apache.cxf.fediz.service.idp.beans;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockRequestContext;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class STSClientActionTest {

    private static final int LOCAL_PORT = 8080;

    @Test
    public void testWsdlWithDefaultPort() {
        String wsdlLocation = "http://someserver/sts";
        STSClientAction action = new STSClientAction();
        action.setWsdlLocation(wsdlLocation);
        callProcessWsdlLocation(action, mockRequestContext());
        assertEquals(wsdlLocation, action.getWsdlLocation());
    }

    @Test
    public void testWsdlWithExplicitPort() {
        String wsdlLocation = "http://someserver:91/sts";
        STSClientAction action = new STSClientAction();
        action.setWsdlLocation(wsdlLocation);
        callProcessWsdlLocation(action, mockRequestContext());
        assertEquals(wsdlLocation, action.getWsdlLocation());
    }

    @Test
    public void testWsdlWithPort0() {
        String wsdlLocation = "http://someserver:0/sts";
        STSClientAction action = new STSClientAction();
        action.setWsdlLocation(wsdlLocation);
        callProcessWsdlLocation(action, mockRequestContext());
        assertEquals("http://someserver:" + LOCAL_PORT + "/sts", action.getWsdlLocation());
    }

    private void callProcessWsdlLocation(STSClientAction action, RequestContext requestContext) {
        Method method = null;
        try {
            method = action.getClass().getDeclaredMethod("processWsdlLocation", RequestContext.class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        method.setAccessible(true);
        try {
            method.invoke(action, requestContext);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Forces local port to pre-defined value to test if it's used
     * by STSClientAction to compute STS urls.
     */
    private RequestContext mockRequestContext() {
        MockRequestContext requestContext = new MockRequestContext();
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setLocalPort(LOCAL_PORT);
        requestContext.getMockExternalContext().setNativeRequest(servletRequest);
        return requestContext;
    }
}
