<!DOCTYPE html>
<html>

<head>
<meta charset="utf-8">
<title>BGP - @yield('title')</title>
<!-- 新 Bootstrap 核心 CSS 文件 -->
<link rel="stylesheet" href="/css/bootstrap.min.css">

<!--link rel="stylesheet" src="/boottable/dist/bootstrap-table.min.css"-->
<link rel="stylesheet" href="/css/gentelella.min.css">

<link rel="stylesheet" href="/css/bootstrap-table.css">

<!-- jQuery文件。务必在bootstrap.min.js 之前引入 -->
<script src="/js/jquery.min.js"></script>

<script src="/js/bootstrap-table.js"</script>>

<!-- 最新的 Bootstrap 核心 JavaScript 文件 -->
<script src="/js/bootstrap.min.js"></script>

<script src="/js/gentelella.min.js"></script>

<style type="text/css">
#myTable thead > tr > th.detail,
#myTable tbody > tr:not(.detail-view) > td:first-of-type {
  display: none;
}

#myTable thead > tr > th:nth-child(2),
#myTable tbody > tr:not(.detail-view) > td:nth-child(2) {
  border-left: none!important;
}
</style>

</head>

<body>
  @section('sidebar')
  <nav class="navbar navbar-inverse" role="navigation">
    <div class="container">
      <div class="navbar-header">
        <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
          <span class="sr-only">Toggle navigation</span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
        </button>
        <a class="navbar-brand" href="#">BGP Data</a>
      </div>
      <div id="navbar" class="navbar-collapse collapse">
        <ul class="nav navbar-nav">
          <li @yield('home')><a href="/">Home</a></li>
          <li @yield('ipquery')><a href="/ipquery">IP Query</a></li>
          <li @yield('links')><a href="/links">Links</a></li>
          <li @yield('monitors')><a href="/monitors">Monitors</a></li>
          <li @yield('origins')><a href="/origins">Origins</a></li>
          <li @yield('asnames')><a href="/asnames">AS Names</a></li>
        </ul>
      </div>
    </div>
  </nav>
  @show
  <div class="container">
    @yield('content')
  </div>
</body>

</html>
