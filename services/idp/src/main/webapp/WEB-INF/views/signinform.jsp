<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<html>
	<head>
		<title>IDP SignIn Request Form</title>
		<style type="text/css">
			.error 			{
								color: #a94442 !important;
								background-color: #f2dede !important;
								border-color: #ebccd1 !important;
							}
			.msg 			{
								padding: 15px;
								border: 1px solid transparent;
								border-radius: 4px;
								color: #31708f;
								background-color: #d9edf7;
								border-color: #bce8f1;
								margin: auto;
								text-align: center;
								margin-top: 5px;
								width: 60%;
							}
			h1				{
								font-size: 24px;
								margin-top: 25px;
							}
			body			{
								font-family:arial;
							}
			label			{
								width: 90px;
								display: inline-block;
							}
			#login_form		{
								width: 250px;
							}
			#submit_button	{
								float: right;
								margin: 5px 12px;
							}
		</style>
	</head>
	<body onload='documentLoaded()'>
		<img src="<c:url value='/images/apache-logo.png' />" alt="Apache Logo" style="margin:5px auto">
		
		<c:if test="${param.error != null}">
			<div class="msg error"><b>Login Failed</b><br />
                Username and password do not match. Please try again.</div>
		</c:if>
		<c:if test="${param.out != null}">
			<div class="msg info"><b>Logout successful</b></div>
		</c:if>
		
		<h1>Fediz IDP Login</h1>
		
		<form:form method="POST" id="signinform" name="signinform" action="login.do">
			<div id="login_form">
				<label for="username">UserId</label>
				<input type="text" id="username" name="username" placeholder="username" />
				<br />
				<label for="password">Password</label>
				<input type="password" id="password" name="password" placeholder="password" />
				<br />
				<!--input type="hidden" id="execution" name="execution" value="${flowExecutionKey}"/-->
				<input type="submit" id="submit_button" name="authenticate" value="Authenticate" />
			</div>
		</form:form>
	</body>
	<script language="javascript">
	    function documentLoaded() {
	        var form = document.signinform;
	        form.username.focus();
	        propagateUriFragment(form);
	    }
	    /**
         * Prepares the form for submission by appending any URI
         * fragment (hash) to the form action in order to propagate it
         * through the re-direct
         * @param form The login form object.
         * @returns the form.
         */
        function propagateUriFragment(form) {
            // Extract the fragment from the browser's current location.
            var hash = decodeURIComponent(self.document.location.hash);

            // The fragment value may not contain a leading # symbol
            if (hash && hash.indexOf("#") === -1) {
                hash = "#" + hash;
            }

            // Append the fragment to the current action so that it persists to the redirected URL.
            form.action = form.action + hash;
            return form;
        }
	</script>
</html>