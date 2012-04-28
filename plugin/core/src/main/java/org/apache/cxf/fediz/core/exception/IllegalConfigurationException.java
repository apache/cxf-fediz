package org.apache.cxf.fediz.core.exception;

public class IllegalConfigurationException extends RuntimeException {

    public IllegalConfigurationException() {
        super();
    }

    public IllegalConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalConfigurationException(String message) {
        super(message);
    }

    public IllegalConfigurationException(Throwable cause) {
        super(cause);
    }

}
