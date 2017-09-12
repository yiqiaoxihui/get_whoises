<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;

class AsnamesController extends Controller
{
    //
    public function index()
    {
        return view('asnames');
    }
    public function store()
    {
        if($_POST['type'] == 'data'){
          $params = json_decode($_POST['data']);
          if(strlen($_POST['content']) > 0){
            if(isset($params->sort)){
              if($_POST['search'] == 'as'){
                $rows = DB::table('whois_as')->where('asnum', 'like', $_POST['content'].'%')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
              else{
                $rows = DB::table('whois_as')->where($_POST['search'], 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
            }
            else{
              if($_POST['search'] == 'as'){
                $rows = DB::table('whois_as')->where('asnum', 'like', $_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
              }
              else{
                $rows = DB::table('whois_as')->where($_POST['search'], 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
              }
            }
            if($_POST['search'] == 'as'){
              $total = DB::table('whois_as')->where('asnum', 'like', $_POST['content'].'%')->count();
            }
            else{
              $total = DB::table('whois_as')->where($_POST['search'], 'like', '%'.$_POST['content'].'%')->count();
            }
          }
          else{
            if(isset($params->sort)){
              $rows = DB::table('whois_as')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
            }
            else{
              $rows = DB::table('whois_as')->skip($params->offset)->take($params->limit)->get();
            }
            $total = DB::table('whois_as')->count(); 
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
          $value = $_POST['value'];
          if ($field == 'message'){
            $row = DB::table('messages')->where('id', $value)->first();
            $row->first = date('Y/m/d H:i:s', $row->first);
            $row->last = date('Y/m/d H:i:s', $row->last);
            $data = array("result" => $row);
          }
          else{
            if ($value[0] ==  '#')
            {
              $row = DB::table('asset')->where('id', substr($value, 1))->first();
              $data = array("result" => $row);
            }
            else
            {
              $row = DB::table('whois_as')->select('asnum as AS', 'name as Name')->where('asnum', $value)->first();
              $data = array("result" => $row);
            }
          }
        }
        return $data;

    }
}
