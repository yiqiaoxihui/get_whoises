<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;

class MonitorsController extends Controller
{
    //
    public function index(){
        return view('monitors');
    }

    public function store()
    {
        if($_POST['type'] == 'data'){
          $params = json_decode($_POST['data']);
          if(strlen($_POST['content']) > 0){
            if(isset($params->sort)){
              if ($_POST['search'] == 'asn'){
                $rows = DB::table('mon_aggrs')->where($_POST['search'], 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
              else{
                $rows = DB::table('mon_aggrs')->where($_POST['search'], 'like', $_POST['content'].'%')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
            }
            else{
              if ($_POST['search'] == 'asn'){
                $rows = DB::table('mon_aggrs')->where($_POST['search'], 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->get();
              }
              else{
                $rows = DB::table('mon_aggrs')->where($_POST['search'], 'like', $_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
              }
            }
            if ($_POST['search'] == 'asn'){
              $total = DB::table('mon_aggrs')->where($_POST['search'], 'like', $_POST['content'])->count();
            }
            else{
              $total = DB::table('mon_aggrs')->where($_POST['search'], 'like', $_POST['content'].'%')->count();
            }
          }
          else{
            if(isset($params->sort)){
              $rows = DB::table('mon_aggrs')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
            }
            else{
              $rows = DB::table('mon_aggrs')->skip($params->offset)->take($params->limit)->get();
            }
            $total = DB::table('mon_aggrs')->count(); 
          }
          foreach($rows as $row){
            $row->first = date('Y/m/d H:i:s', $row->first);
            $row->last = date('Y/m/d H:i:s', $row->last);
          }
          $idstart = (int) $params->offset + 1;
          foreach($rows as $row)
          {
            $row->id = $idstart;
            $idstart ++;
          }
          $data = array("rows" => $rows, "total" => $total);
        }
        elseif($_POST['type'] == 'detail'){
          $field = $_POST['field'];
          $msg = DB::table('messages')->where('id', $field['message'])->first();
          $msg->first = date('Y/m/d H:i:s', $msg->first);
          $msg->last = date('Y/m/d H:i:s', $msg->last);

          if ($field['asn'][0] == '#'){
            $row = DB::table('asset')->select('asset as Name')->where('id', substr($field['asn'], 1))->first();
            $asn = array("result" => $row);
          }
          else{
            $row = DB::table('whois_as')->select('asnum as AS', 'asname as Name', 'orgname as Organization', 'country as Country')->where('asnum', $field['asn'])->first();
            if ($row->Organization != ''){
              $row->Name = $row->Name . ', ' . $row->Organization;  
            }
            if ($row->Country != ''){
              $row->Name = $row->Name . ', ' . $row->Country;
            }
            unset($row->Organization);
            unset($row->Country);
            if ($row->Name == ""){
              $row->Name = "Unknown";
            }
            $asn = array("result" => $row);
          }
          $data = array('asn' => $asn, 'message' => $msg);
        }
        return $data;
    }

}
