@extends('layouts.blank')

@push('stylesheets')
    <!-- Example -->
    <!--<link href=" <link href="{{ asset("css/myFile.min.css") }}" rel="stylesheet">" rel="stylesheet">-->
@endpush

@section('main_container')
  <div class="right_col" role="main">
    <center><h1>Whois Query</h1></center>
    <form id="toolbar" form="bs-example bs-example-form" role="form" onsubmit="searchData(); return false;">
      <div class="input-group col-md-4 col-md-offset-8">
        <div class="input-group-btn">
          <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown">
            <span id="type">Ip</span>
            <span class="caret"></span>
          </button>
          <ul class="dropdown-menu">
            <li>
              <a onclick="changeType(this)">Ip</a>
            </li>
            <li>
              <a onclick="changeType(this)">content</a>
            </li>
          </ul>
        </div>
        <input id="content" type="text" class="form-control" value="">
        <span class="input-group-btn">
          <button class="btn btn-default" type="submit">Search</button>
        </span>
      </div><!-- /input-group -->
    </form>
    <table id="myTable"
           data-toggle="table" 
           data-method="post"
           data-side-pagination="server"
           data-pagination="true"
           data-page-list="[5, 10, 20, 50, 100, 200]"
           data-ajax="ajaxRequest"
           data-detail-view="true"
           data-detail-formatter="detailFormatter"
           data-toolbar="#toolbar"
           data-toolbar-align="right"
           data-url="whois">
      <thead>
        <tr>
          <th data-field="id">id</th>
          <!-- <th data-field="_id" hidden>ID</th> -->
          <th data-field="ip_begin" data-sortable="ture">ip_begin</th>
          <th data-field="ip_end">ip_end</th>

        </tr>
      </thead>
    </table>
  </div>
@endsection

@push('scripts')
  <script>
    var $table = $('#myTable');
    $table.on('click-cell.bs.table', clickCell);
    var $searchType = $('#type');
    var $searchContent = $('#content');
    $searchContent.val('{!!$input!!}');
    var column = '';
    $.ajaxSetup({
      url: "whois",
      type: "POST",
      headers: { 'X-CSRF-TOKEN' : '{{ csrf_token() }}' }
    });
    /*
    function queryParams(params){
      var temp = {
        limit: params.limit,
        offset: params.offset,
        sort: params.sort,
        order: params.order
      };
      return temp;
    }*/
    function numberToIp(number) {   
      var ip = ""; 
      if(number <= 0) { 
        return ip; 
      } 
      var ip3 = (number << 0 ) >>> 24; 
      var ip2 = (number << 8 ) >>> 24; 
      var ip1 = (number << 16) >>> 24; 
      var ip0 = (number << 24) >>> 24 
       
      ip += ip3 + "." + ip2 + "." + ip1 + "." + ip0; 
       
      return ip;   
    } 
    function ajaxRequest(params){
      var type = $searchType.html().toLowerCase(); 
      var content = $searchContent.val();
      console.log("ajaxRequest,type:"+type+"content:"+content+"data:"+params.data);
      $.ajax({
        data: {type: 'data',data:params.data, search: type, content: content},
        success: function(data, status){
          for(var item in data['rows']){
            data['rows'][item]['ip_end']=numberToIp(data['rows'][item]['ip_end']);
            data['rows'][item]['ip_begin']=numberToIp(data['rows'][item]['ip_begin']);
            //console.log(data['rows'][item]['ip_end']);
          }
          params.success(data);
        }
      })
    }
    /*
    function identifierFormatter(value, row, index) {
      return [
        '<a class="like" href="javascript:void(0)" title="Like">',
        value,
        '</a>'].join('');
    }
    */
    function clickCell(e, field, value, row, $element){
      $table.bootstrapTable('collapseAllRows');
      var index = $element.parent().data('index');
      $table.bootstrapTable('expandRow', index );
    }
    function detailFormatter(index, row) {
      var html = [];
      var id= row['_id'];
      $.ajax({
        async: false,
        data:{type: 'detail', id: id},
        success:function(data){
          var content=data.message.content;
          console.log("id:"+id+" detail:"+content);
          content=content.replace(/\n/g,"</br>");
          html.push('<p style="word-wrap:break-word; word-break:break-all; width:auto;height:400px;overflow-y:scroll;">' + content + '</p>');
        }
      });
      return html.join('');
    }
    function changeType(obj){
      $searchType.html($(obj).html());
    }
    function searchData(){
      var searchVal = $searchContent.val();
      var searchType = $searchType.html().toLowerCase();
      $table.bootstrapTable('selectPage', 1);
      return false;
    }
  </script>

@endpush
