package org.apache.cxf.fediz.core.spi;

import javax.security.auth.callback.Callback;
import javax.servlet.http.HttpServletRequest;

public abstract class AbstractServletCallback implements Callback {

    protected HttpServletRequest request = null;

    public AbstractServletCallback(HttpServletRequest request) {
        super();
        this.request = request;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

}
