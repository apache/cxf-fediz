<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@page import="java.util.Map"%>
<%@page import="org.apache.cxf.fediz.service.idp.model.IDPConfig"%>
<%@page import="org.apache.cxf.fediz.service.idp.model.TrustedIDPConfig"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<html>
<head>
<title>Trusted IDP List</title>
</head>
<body>
	<h1>Trusted IDP List</h1>
	<i>Where are you from? Please, select one Identity Provider in the list which is able to authenticate you. </i>
	<form:form method="POST" id="idplist" name="idplist">
		<br />
        <% IDPConfig idpConfig = (IDPConfig)request.getAttribute("idpConfig");
        Map<String, TrustedIDPConfig> trustedIDPs = idpConfig.getTrustedIDPs(); %>
      <select name="whr">
        <option value="<%=idpConfig.getRealm()%>" selected="selected" ><%=idpConfig.getServiceDescription()%></option>
        <% for (TrustedIDPConfig trustedIDP : trustedIDPs.values()) { %>
        <option value="<%=trustedIDP.getRealm()%>"><%=trustedIDP.getDescription()%></option>
        <% } %>
      </select>
      <br />
      <input type="hidden" id="execution" name="execution" value="${flowExecutionKey}"/>
      <br />
      <input type="submit" name="_eventId_submit" value="Select Home Realm" />
      <input type="submit" name="_eventId_cancel" value="Cancel" />
    </form:form>
</body>
</html>
