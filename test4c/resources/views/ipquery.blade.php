@extends('layouts.blank')

@push('stylesheets')
    <!-- Example -->
    <!--<link href=" <link href="{{ asset("css/myFile.min.css") }}" rel="stylesheet">" rel="stylesheet">-->
@endpush

@section('main_container')
  <div class="right_col" role="main">
  <div class="col-md-12">
    <center><h1>IP Query</h1></center>
    <br/><br/><br/>
    <form id="toolbar" form="bs-example bs-example-form" role="form" onsubmit="searchData(); return false;">
      <div class="input-group col-md-6 col-md-offset-3">
        <input id="content" type="text" class="form-control" value="">
        <span class="input-group-btn">
          <button class="btn btn-default" type="submit">Search</button>
        </span>
      </div><!-- /input-group -->
    </form>
    <div id="noresult"><center><h3>No result!</h3></center></div>
    <div id="tablediv">
    <br/>
    <table id="myTable"
         data-toggle="table" 
         >
      <thead>
        <tr>
          <th data-field="prefix" data-formatter="identifierFormatter">Prefix</th>
          <th data-field="as">AS</th>
          <th data-field="asname">AS Name</th>
        </tr>
      </thead>
    </table>
    </div>
  </div>
  </div>
@endsection

@push("scripts")
  <script>
    var $table = $('#myTable');
    $table.on('click-cell.bs.table', clickCell);
    var $div = $('#tablediv');
    var $noresult = $('#noresult');
    $noresult.hide();
    $div.hide();
    var $input = $('#content');
    var $searchContent = $('#content');
    var column = '';
    $.ajaxSetup({
      url: "/ipquery",
      type: "POST",
      headers: { 'X-CSRF-TOKEN' : '{{ csrf_token() }}' }
    });
    function identifierFormatter(value, row, index) {
      return [
        '<a class="like" href="javascript:void(0)" title="Like">',
        value,
        '</a>'].join('');
    }
    function searchData(){
      var result;
      var content = $input.val();
      var row = [];
      $.ajax({
        async: false,
        data: {type: 'search', input: content},
        success:function(data){
          result = data;
        }
      });
      if(result == "noresult")
      {
        $noresult.show();
        $div.hide();
      }
      else{
        $noresult.hide();
        $div.show();
        $table.bootstrapTable('load', result);
      }
      return false;
    }
    function clickCell(e, field, value, row, $element){
      if (field == 'prefix'){
        //window.location.href = "origins?prefix=" + value;
        /*
        $.ajax({
          async: false,
          contentType:"application/x-www-form-urlencoded",
          data:{type: 'prefix', input: value},
        });
        */
        var form = $('<form method="post"><?php echo method_field('POST'); ?><?php echo csrf_field(); ?></form>');
        form.attr({"action":"/origins"});
        var input = $("<input type='hidden'>");
        input.attr({"name":"type"});
        input.val("data");
        form.append(input);
        input = $("<input type='hidden'>");
        input.attr({"name":"data"});
        input.val('{"order":"asc", "offset":"0", "limit":"10"}');
        form.append(input);
        input = $("<input type='hidden'>");
        input.attr({"name":"search"});
        input.val('prefix');
        form.append(input);
        input = $("<input type='hidden'>");
        input.attr({"name":"content"});
        input.val(value);
        form.append(input);
        input = $("<input type='hidden'>");
        input.attr({"name":"from"});
        input.val('others');
        form.append(input);
        $(document.body).append(form);
        form.submit();
      }
    }
  </script>
@endpush
