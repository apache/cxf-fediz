package org.apache.cxf.fediz.core.config;

import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;

public class HomeRealm {
    private org.apache.cxf.fediz.core.config.jaxb.HomeRealm homeRealm;

    public HomeRealm(org.apache.cxf.fediz.core.config.jaxb.HomeRealm homeRealm) {
        super();
        this.homeRealm = homeRealm;
    }

    protected org.apache.cxf.fediz.core.config.jaxb.HomeRealm getHomeRealm() {
        return homeRealm;
    }

    protected void setHomeRealm(org.apache.cxf.fediz.core.config.jaxb.HomeRealm homeRealm) {
        this.homeRealm = homeRealm;
    }

    public ArgumentType getType() {
        return homeRealm.getType();
    }

    public int hashCode() {
        return homeRealm.hashCode();
    }

    public void setType(ArgumentType value) {
        homeRealm.setType(value);
    }

    public String getValue() {
        return homeRealm.getValue();
    }

    public void setValue(String value) {
        homeRealm.setValue(value);
    }

    public boolean equals(Object obj) {
        return homeRealm.equals(obj);
    }

    public String toString() {
        return homeRealm.toString();
    }

    
    
}