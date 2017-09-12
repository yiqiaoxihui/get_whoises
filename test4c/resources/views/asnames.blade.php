@extends('bgp')

@section('title', 'as names')

@section('asnames')
class = "active"
@endsection

@section('content')
  <div class="col-md-12">
  <center><h1>AS Names</h1></center>
  <form id="toolbar" form="bs-example bs-example-form" role="form" onsubmit="searchData(); return false;">
    <div class="input-group col-md-4 col-md-offset-8">
      <div class="input-group-btn">
        <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown">
          <span id="type">AS</span>
          <span class="caret"></span>
        </button>
        <ul class="dropdown-menu">
          <li>
            <a onclick="changeType(this)">AS</a>
          </li>
          <li>
            <a onclick="changeType(this)">Name</a>
          </li>
          <li>
            <a onclick="changeType(this)">Organization</a>
          </li>
          <li>
            <a onclick="changeType(this)">Country</a>
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
         data-url="/asnames">
    <thead>
      <tr>
        <th data-field="id">ID</th>
        <th data-field="asnum" data-formatter="identifierFormatter">AS</th>
        <th data-field="asname">Name</th>
        <th data-field="orgname">Organization Name</th>
        <th data-field="country">Country</th>
      </tr>
    </thead>
  </table>
  <script>
    var $table = $('#myTable');
    $table.on('click-cell.bs.table', clickCell);
    var $searchType = $('#type');
    var $searchContent = $('#content');
    var column = '';
    $.ajaxSetup({
      url: "/asnames",
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
    function ajaxRequest(params){
      var type = $searchType.html(); 
      var search_type = 'as';
      if (type == 'AS'){
        search_type = 'as';
      }
      else if (type == 'Name'){
        search_type = 'name';
      }
      else if (type == 'Organization'){
        search_type = 'orgname';
      }
      else if (type == 'Country'){
        search_type = 'country';
      }
      else{
        search_type = 'as';
      }
      var content = $searchContent.val();
      $.ajax({
        data: {type: 'data',data:params.data, search: search_type, content: content},
        success: function(data, status){
          params.success(data);
        }
      })
    }
    function identifierFormatter(value, row, index) {
      return [
        '<a class="like" href="javascript:void(0)" title="Like">',
        value,
        '</a>'].join('');
    }
    function clickCell(e, field, value, row, $element){
      $table.bootstrapTable('collapseAllRows');
      if(field == 'as'){
        var index = $element.parent().data('index');
        column = field; 
        $table.bootstrapTable('expandRow', index );
      }
    }
    function detailFormatter(index, row) {
      var html = [];
      $.ajax({
        async: false,
        data:{type: 'detail', field:column, value:row[column]},
        success: function(data){
          $.each(data.result, function(key, value){
            html.push('<p style="word-wrap:break-word; word-break:break-all; width:auto;"><b>' + key + ':</b> ' + value + '</p>');
          });
        }
      });
      return html.join('');
    }
    function changeType(obj){
      $searchType.html($(obj).html());
    }
    function searchData(){
      /*
      var searchVal = $searchContent.val();
      var searchType = $searchType.html().toLowerCase();
      */
      $table.bootstrapTable('selectPage', 1);
      $table.bootstrapTable('refresh');
      return false;
    }
  </script>
  </div>
@endsection

