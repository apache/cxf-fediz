<%@ page import="java.util.Set"%>
<%@ page import="java.util.HashSet"%>
<%@ page import="java.lang.reflect.Field"%>
<%@ page import="org.apache.cxf.fediz.service.idp.FederationFilter"%>
<%@ page import="org.apache.cxf.fediz.service.idp.HttpFormAuthenticationFilter"%>
<%@ page import="org.apache.cxf.fediz.service.idp.IdpServlet"%>

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>IDP SignIn Request Form</title>
</head>
<body>
	<form method="POST" name="signinform">
		<%--
			Replicating the context.
		--%>
		<%
		Set<String> ctx = new HashSet<String>();
		Field[] fields = FederationFilter.class.getFields();
		for (Field f : fields) {
			if(f.getName().startsWith("PARAM_") && String.class.equals(f.getType())) { 
				String key = (String) f.get(null);
				Object value = request.getAttribute(key);
				if(null != value && value instanceof String) {
					%>
		<input type="hidden" name="<%=key%>" value="<%=value%>" readonly="readonly" />
					<%
				}
			}
		}
		%>
		<input type="hidden" name="<%=HttpFormAuthenticationFilter.PARAM_TAG%>" value="<%=HttpFormAuthenticationFilter.PARAM_TAG%>" readonly="readonly" />
		userid :
		<input type="text" name="<%=HttpFormAuthenticationFilter.PARAM_USERNAME%>" size="32" /><br />
		password :
		<input type="password" name="<%=HttpFormAuthenticationFilter.PARAM_PASSWORD%>" size="32" /><br />
		<input type="submit" value="Authenticate" />
	</form>
</body>
</html>