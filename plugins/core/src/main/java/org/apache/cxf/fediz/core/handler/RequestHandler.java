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
package org.apache.cxf.fediz.core.handler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface RequestHandler {

    /**
     * @param request Check if handler can handle this given request
     * @return Returns true if handler can handle provided request, otherwise handler returns false.
     */
    boolean canHandleRequest(HttpServletRequest request);

    /**
     * After ensuring that this Handler can handle the given request this method will do the actual handling.
     *
     * @param request Request to be handled.
     * @param response Response to be populated.
     * @return Returns true if request handling was successful.
     */
    boolean handleRequest(HttpServletRequest request, HttpServletResponse response);
}
