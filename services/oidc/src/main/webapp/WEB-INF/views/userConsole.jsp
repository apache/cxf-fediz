<%@ page
	import="javax.servlet.http.HttpServletRequest,java.util.Map,java.util.Iterator,org.apache.cxf.fediz.service.oidc.console.UserConsole"%>
<%
    UserConsole account = (UserConsole)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    }
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>User Account</title>
    <link rel="stylesheet" href="<%= basePath %>static/styles.css">
</head>
<body>
    <h2 class="center">Welcome to Fediz OpenId Connect Console</h2>
	<p><a href="<%=basePath%>console/clients">Client Registrations</a></p>
</body>
</html>
