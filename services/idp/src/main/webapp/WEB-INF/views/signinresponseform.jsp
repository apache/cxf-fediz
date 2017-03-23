<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<html>
<head>
<title>IDP SignIn Response Form</title>
</head>
<body onload='documentLoaded()'>
    <form:form method="POST" id="signinresponseform" name="signinresponseform" action="${fedAction}" htmlEscape="true">
        <input type="hidden" name="wa" value="wsignin1.0" /><br />
        <input type="hidden" name="wresult" value="${fedWResult}" /><br />
        <% String wctx = (String)request.getAttribute("fedWCtx");
           if (wctx != null && !wctx.isEmpty()) { %>
            <input type="hidden" name="wctx" value="${fedWCtx}" /><br />
        <% } %>
        <input type="hidden" name="wtrealm" value="${fedWTrealm}" /><br />
        <noscript>
        <p>Script is disabled. Click Submit to continue.</p>
        <input type="submit" name="_eventId_submit" value="Submit" /><br />
        </noscript>
    </form:form>
    <script language="javascript">
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
        function documentLoaded() {
            propagateUriFragment(document.forms[0]);
            window.setTimeout('document.forms[0].submit()',0);
        }
    </script>
</body>
</html>
