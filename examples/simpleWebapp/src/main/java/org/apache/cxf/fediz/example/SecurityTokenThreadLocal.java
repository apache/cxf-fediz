package org.apache.cxf.fediz.example;

import org.w3c.dom.Element;


/**
* Thread local storage for security token
*/
public class SecurityTokenThreadLocal {

	private static final ThreadLocal<Element> threadToken = 
	       new ThreadLocal<Element>() {
	};
	
	public static void setToken(Element token) {
		threadToken.set(token);
	}
	
	public static Element getToken() {
		return threadToken.get();
	}
}