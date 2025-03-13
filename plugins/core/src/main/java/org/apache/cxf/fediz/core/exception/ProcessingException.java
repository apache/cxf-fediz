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

package org.apache.cxf.fediz.core.exception;

public class ProcessingException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public enum TYPE {
        TOKEN_EXPIRED,
        TOKEN_REPLAY,
        BAD_REQUEST,
        INVALID_REQUEST,
        ISSUER_NOT_TRUSTED,
        TOKEN_INVALID,
        TOKEN_NO_SIGNATURE
    }

    /**
     * A map of Fault Code to Fault Strings
     */
    private static final java.util.Map<TYPE, String> TYPE_MAP =
            new java.util.EnumMap<>(TYPE.class);

    static {
        TYPE_MAP.put(TYPE.BAD_REQUEST, "The specified request is not understood");
        TYPE_MAP.put(TYPE.INVALID_REQUEST, "The request was invalid or malformed");
        TYPE_MAP.put(TYPE.TOKEN_REPLAY, "Security token already used (replay)");
        TYPE_MAP.put(TYPE.TOKEN_EXPIRED, "Security token expired");
        TYPE_MAP.put(TYPE.ISSUER_NOT_TRUSTED, "Security token issuer not trusted");
        TYPE_MAP.put(TYPE.TOKEN_INVALID, "Security token has been revoked");
        TYPE_MAP.put(TYPE.TOKEN_NO_SIGNATURE, "Security token has no signature");
    }

    private TYPE type;


    public ProcessingException(String message) {
        super(message);
    }

    public ProcessingException(String message, TYPE type) {
        super(message);
        this.type = type;
    }

    public ProcessingException(TYPE type) {
        this.type = type;
    }

    public ProcessingException(String message, Throwable e) {
        super(message, e);
    }

    public ProcessingException(String message, Throwable e, TYPE type) {
        super(message, e);
        this.type = type;
    }

    public void setType(TYPE type) {
        this.type = type;
    }

    public TYPE getType() {
        return type;
    }

    @Override
    public String getMessage() {
        if (type != null && TYPE_MAP.get(type) != null) {
            return TYPE_MAP.get(type);
        }
        return super.getMessage();
    }

}
