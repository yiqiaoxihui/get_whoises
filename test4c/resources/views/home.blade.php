@extends('layouts.blank')

@push('stylesheets')
    <!-- Example -->
    <!--<link href=" <link href="{{ asset("css/myFile.min.css") }}" rel="stylesheet">" rel="stylesheet">-->
    <style>
      .x_title h2 {
        font-size: 24px;
      }
      .panel_toolbox {
        margin-top: 5px;
        min-width: 24px;
      }
      .x_content .tile_count {
        margin: 0 0 0 0;
      }
      .x_content .tile_count .tile_stats_count:first-child:before {
        border-left: 2px solid #ADB2B5;
      }
      .x_content .tile_count .tile_stats_count:before {
        margin: 0 0 0 0;
      }
      .x_content .tile_count .tile_stats_count {
        border-bottom: 1px solid #D9DEE4;
      }
      .x_content .tile_count .tile_stats_count span {
        font-size: 16px;
      }
      .x_content .tile_count .tile_stats_count .count {
        line-height: 20px;
        font-size: 16px;
      }
      .tile_count .tile_stats_count .count {
        font-size: 30px;
        line-height: normal;
      }
      .tile_count .tile_stats_count span {
        line-height: normal;
      }
    </style>
@endpush

@section('main_container')

    <!-- page content -->
    <div class="right_col" role="main">
      <div class="col-md-12 col-sm-12 col-xs-12">

        <div class="row tile_count">
          <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
            <span class="count_top"><i class="fa fa-user"></i> Total ASes</span>
            <div class="count" id = "t_ases">0</div>
            <!--<span class="count_bottom"><i class="green" id="u_ases"> 0 </i> From last Week</span>-->
          </div>

          <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
            <span class="count_top"><i class="fa fa-user"></i> Total AS Links</span>
            <div class="count" id = "t_links">0</div>
            <!--<span class="count_bottom"><i class="green" id="u_ases"> 0 </i> From last Week</span>-->
          </div>

          <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
            <span class="count_top"><i class="fa fa-user"></i> Total Prefixes</span>
            <div class="count" id = "t_pres">0</div>
            <!--<span class="count_bottom"><i class="green" id="u_ases"> 0 </i> From last Week</span>-->
          </div>

          <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
            <span class="count_top"><i class="fa fa-user"></i> Total Monitors</span>
            <div class="count" id = "t_mons">0</div>
            <!--<span class="count_bottom"><i class="green" id="u_ases"> 0 </i> From last Week</span>-->
          </div>

          <div class="col-md-6 col-sm-12 col-xs-12 tile_stats_count">
            <span class="count_top"><i class="fa fa-calendar"></i> Oldest Record</span>
            <div class="count" id = "oldest">0</div>
            <!--<span class="count_bottom"><i class="green" id="u_ases"> 0 </i> From last Week</span>-->
          </div>

          <div class="col-md-6 col-sm-12 col-xs-12 tile_stats_count">
            <span class="count_top"><i class="fa fa-calendar"></i> Latest Record</span>
            <div class="count" id = "latest">0</div>
            <!--<span class="count_bottom"><i class="green" id="u_ases"> 0 </i> From last Week</span>-->
          </div>
        </div>

        <div class="row">
          <div class="x_panel title">
            <div class="x_title">
              <h2>Links</h2>
              <ul class="nav navbar-right panel_toolbox">
                <li>
                  <a class="collapse-link"><i class="fa fa-chevron-up"></i></a>
                </li>
              </ul>
              <div class="clearfix"></div>
            </div>
  
            <div class="x_content">
              <div class="tile_count">
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Total</span>
                  <div class="count" id="l_total">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Updated</span>
                  <div class="count" id="l_updated">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-calendar"></i> Oldest</span>
                  <div class="count" id="l_oldest">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-calendar"></i> Latest</span>
                  <div class="count" id="l_latest">0</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="row">
          <div class="x_panel title">
            <div class="x_title">
              <h2>Monitors</h2>
              <ul class="nav navbar-right panel_toolbox">
                <li>
                  <a class="collapse-link"><i class="fa fa-chevron-up"></i></a>
                </li>
              </ul>
              <div class="clearfix"></div>
            </div>
  
            <div class="x_content">
              <div class="tile_count">
                <div class="col-md-2 col-sm-4 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Total</span>
                  <div class="count" id="m_total">0</div>
                </div>
                <div class="col-md-2 col-sm-4 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Aggregation</span>
                  <div class="count" id="a_mons">0</div>
                </div>
                <div class="col-md-2 col-sm-4 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Updated</span>
                  <div class="count" id="m_updated">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-calendar"></i> Oldest</span>
                  <div class="count" id="m_oldest">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-calendar"></i> Latest</span>
                  <div class="count" id="m_latest">0</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="row">
          <div class="x_panel title">
            <div class="x_title">
              <h2>Origins</h2>
              <ul class="nav navbar-right panel_toolbox">
                <li>
                  <a class="collapse-link"><i class="fa fa-chevron-up"></i></a>
                </li>
              </ul>
              <div class="clearfix"></div>
            </div>
  
            <div class="x_content">
              <div class="tile_count">
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Total</span>
                  <div class="count" id="o_total">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-sitemap"></i> Updated</span>
                  <div class="count" id="o_updated">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-calendar"></i> Oldest</span>
                  <div class="count" id="o_oldest">0</div>
                </div>
                <div class="col-md-3 col-sm-6 col-xs-12 tile_stats_count">
                  <span class="count_top"><i class="fa fa-calendar"></i> Latest</span>
                  <div class="count" id="o_latest">0</div>
                </div>
              </div>
            </div>
          </div>
        </div>
        
      </div>

    </div>
    <!-- /page content -->
@endsection

@push('scripts')
    <script>
      $.ajaxSetup({
        url: "/",
        type: "POST",
        headers: { 'X-CSRF-TOKEN' : '{{ csrf_token() }}' }
      });
      var links = $('#links');
      var monitors = $('#monitors');
      var origins = $('#origins');
      $.ajax({
        data:{type:'init'},
        success:function(data){
          $('#l_total').html(data.change.c_links);
          $('#l_oldest').html(data.change.o_link);
          $('#l_latest').html(data.change.l_link);
          $('#l_updated').html(data.change.n_links);
          $('#m_total').html(data.change.c_monitors);
          $('#m_oldest').html(data.change.o_mon);
          $('#m_latest').html(data.change.l_mon);
          $('#m_updated').html(data.change.n_monitors);
          $('#a_mons').html(data.change.a_mons);
          $('#o_total').html(data.change.c_origins);
          $('#o_oldest').html(data.change.o_orig);
          $('#o_latest').html(data.change.l_orig);
          $('#o_updated').html(data.change.n_origins);
          $('#t_ases').html(data.change.ases);
          $('#t_pres').html(data.change.prefixes);
          $('#t_mons').html(data.change.a_mons);
          $('#t_links').html(data.change.c_links);
          $('#oldest').html(data.change.oldest);
          $('#latest').html(data.change.latest);
        }
      });
    </script>

@endpush
