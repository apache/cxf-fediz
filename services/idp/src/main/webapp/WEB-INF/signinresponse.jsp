<html>
<head>
<title>IDP SignIn Response Form</title>
</head>
<body>
<form method="POST" name="hiddenform"
	action="<%= ((String)request.getAttribute("fed.action")) %>">
<input type="hidden" name="wa" value="wsignin1.0" /><input
	type="hidden" name="wresult"
	value="<%= ((String)request.getAttribute("fed.wresult")) %>" />
<input
	type="hidden" name="wctx"
	value="<%= ((String)request.getAttribute("fed.wctx")) %>" />
<noscript>
<p>Script is disabled. Click Submit to continue.</p>
<input type="submit" value="Submit" />
</noscript>
</form>
<script language="javascript">window.setTimeout('document.forms[0].submit()',
0);</script>
</body>
</html>