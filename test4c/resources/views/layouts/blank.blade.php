<!DOCTYPE html>
<html lang="en">

    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

        <!-- Meta, title, CSS, favicons, etc. -->
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>BGP</title>

        <!-- Bootstrap -->
        <link href="{{ asset("css/bootstrap.min.css") }}" rel="stylesheet">
        <!-- Font Awesome -->
        <link href="{{ asset("css/font-awesome.min.css") }}" rel="stylesheet">
        <!-- Custom Theme Style -->
        <link href="{{ asset("css/gentelella.min.css") }}" rel="stylesheet">

        <link href="{{ asset("css/bootstrap-table.css") }}" rel="stylesheet">

        @stack('stylesheets')
        <style type="text/css">
          /*
          #myTable thead > tr > th.detail,
          #myTable tbody > tr:not(.detail-view) > td:first-of-type {
            display: none;
          }

          #myTable thead > tr > th:nth-child(2),
          #myTable tbody > tr:not(.detail-view) > td:nth-child(2) {
            border-left: none!important;
          }
          */
          .detail {
            display: table-cell;
          }
          body {
            color: #000000;
          }
          body .container.body .right_col {
          }
        </style>


    </head>

    <body class="nav-md">
        <div class="container body">
            <div class="main_container">

                @include('includes/sidebar')

                @include('includes/topbar')

                @yield('main_container')

                @include('includes/footer')

            </div>
        </div>

        <!-- jQuery -->
        <script src="{{ asset("js/jquery.min.js") }}"></script>
        <!-- Bootstrap -->
        <script src="{{ asset("js/bootstrap.min.js") }}"></script>
        <!-- Custom Theme Scripts -->
        <script src="{{ asset("js/gentelella.min.js") }}"></script>

        <script src="{{ asset("js/bootstrap-table.js") }}"></script>


        @stack('scripts')

    </body>
</html>
