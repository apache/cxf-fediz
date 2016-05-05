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
<style TYPE="text/css">
<!--
h2 {
	font-size: 1.5em;
	font-family: verdana, arial, helvetica, sans-serif;
	margin: 0;
	text-align: center;
}

.header-text {
	border-bottom: 1px solid gray;
	padding: 24px 0;
	margin: 12px 36px 12px;
}

label {
	font-weight: bold;
	margin-bottom: 9px;
	display: block;
	white-space: normal;
}

.form {
	max-width: 425px;
	margin-bottom: 25px;
	margin-left: auto;
	margin-right: auto;
}

.form-line {
	margin: 6 0 6 0;
	padding: 12 36 12 36;
}

.form-required {
	color: red;
	margin-left: 5px;
}

input, select, button {
	width: 100%;
}

.form-submit-button {
	padding: 4px;
	text-align: center;
}
-->
</style>
</head>
<body>
    <h2>Welcome to Fediz OpenId Connect Console</h2>
	<p><a href="<%=basePath%>console/clients">Client Registrations</a></p>
</body>
</html>
