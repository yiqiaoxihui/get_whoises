<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Whois;
class WhoisController extends Controller
{
    //
    public function index(){
    	$count=Whois::count();
    	echo $count;
        return view('whois', ['input' => '']);
    }
    public function store()
    {
        if(isset($_POST['from'])){
          return view('origins', ['input' => $_POST['content']]);
        }
        else{
          if($_POST['type'] == 'data'){
            $params = json_decode($_POST['data']);
            if(strlen($_POST['content']) > 0){
              if(isset($params->sort)){
                if ($_POST['search'] == 'ip'){
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  echo $ip_n;
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
                }
                else{
                  $rows = Whois::where('content', 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
                }
              }
              else{
                if ($_POST['search'] == 'ip'){
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->get();
                }
                else{
                  $rows = Whois::where('content', 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
                }
              }
              if ($_POST['search'] == 'ip'){
                $total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
              }
              else{
                $total = Whois::where('content', 'like', '%'.$_POST['content'].'%')->count();
              }
            }
            else{
              if(isset($params->sort)){
                $rows = Whois::skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
              else{
                $rows = Whois::skip($params->offset)->take($params->limit)->get();
              }
              $total = Whois::count(); 
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
            $id = $_POST['id'];
            $msg = Whois::where('_id', $id)->first();
            $msg->first = date('Y/m/d H:i:s', $msg->first);
            $msg->last = date('Y/m/d H:i:s', $msg->last);
            $data = array('message' => $msg);
          }
          return $data;
        }
    }
}
