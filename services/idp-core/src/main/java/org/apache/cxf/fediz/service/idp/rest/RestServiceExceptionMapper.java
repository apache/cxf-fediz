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
package org.apache.cxf.fediz.service.idp.rest;

import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.access.AccessDeniedException;

@Provider
public class RestServiceExceptionMapper implements ExceptionMapper<Exception> {

    public static final String APPLICATION_ERROR_CODE = "X-Application-Error-Code";

    public static final String APPLICATION_ERROR_INFO = "X-Application-Error-Info";

    private static final String BASIC_REALM_UNAUTHORIZED = "Basic realm=\"Apache Fediz authentication\"";

    private static final Logger LOG = LoggerFactory.getLogger(RestServiceExceptionMapper.class);

    @Override
    public Response toResponse(final Exception ex) {
        LOG.warn("Exception occured processing REST request: " + ex.getMessage(), ex);

        if (ex instanceof AccessDeniedException) {
            return Response.status(Response.Status.UNAUTHORIZED).
                    header(HttpHeaders.WWW_AUTHENTICATE, BASIC_REALM_UNAUTHORIZED).
                    build();
        }
        if (ex instanceof ConstraintViolationException) {
            ConstraintViolationException cve = (ConstraintViolationException)ex;
            LOG.debug("{}\n{}", ex.getMessage(), cve.getConstraintViolations().toString());
            return buildResponse(Response.Status.BAD_REQUEST, ex);
        }
        if (ex instanceof DataIntegrityViolationException) {
            return buildResponse(Response.Status.CONFLICT, ex);
        }

        if (ex instanceof EmptyResultDataAccessException) {
            return buildResponse(Response.Status.NOT_FOUND, ex);
        }

        if (ex instanceof DataRetrievalFailureException) {
            return buildResponse(Response.Status.NOT_FOUND, ex);
        }

        // Rest is interpreted as InternalServerError
        return buildResponse(Response.Status.INTERNAL_SERVER_ERROR, ex);
    }

    Response buildResponse(final Status status, final Exception ex) {
        ResponseBuilder responseBuilder = Response.status(status);
        return responseBuilder.header(APPLICATION_ERROR_CODE, ex.getClass().getName())
                              .header(APPLICATION_ERROR_INFO, ex.getMessage())
                              .status(status).build();
    }

}
