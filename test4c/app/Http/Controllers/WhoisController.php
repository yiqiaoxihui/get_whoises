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

    public function whois_api(Request $request){
      $ip=$request->ip;
      $result=array();
      if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip)){
        $ip_n = bindec(decbin(ip2long($ip)));
        $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
        $i=0;
        foreach($rows as $k=>$row)
        {
          //print_r($row);
          //print_r("</br>");
          $data=$row->content;
          preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
          if(count($ips)>1){
            //print_r(count($ips));
            //print_r($ips[count($ips)-1][1]);
            $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
            $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
            if($ip_n>=$ip_begin && $ip_n<=$ip_end){
              //unset($rows[$k]);
              $result[$i]=$row;
/*              print_r($ips[count($ips)-1][1]);
              echo "~";
              print_r($ips[count($ips)-1][2]);
              print_r("</br>");*/
              $i++;
            }

          }
        }
        //print_r(count($result));
        //return json_encode($result);
      }else{
        return -1;
      }
      

    }
    public function ip_n_to_ip($ip,$ipn){
      $elements=explode(".", $ip);
      $len=count($elements);
      if($len==1){
        $ip=$ip.'.0.0.0';
      }elseif($len==2) {
        $ip=$ip.'.0.0';
      }elseif($len==3) {
        $ip=$ip.'.0';
      }else{

      }
      //echo "</br>--1---";
      //print_r($elements);
      //echo "</br>";
      print_r($ip);
      if (intval($ipn)<32 & intval($ipn)>0){
        #print ip_num[1]
        $ip_begin="";
        $ip_end="";
        //qu zheng
        $ip_int=floor(intval($ipn)/8);
        $ip_rem=intval($ipn)%8;
        for($i=0;$i<$ip_int;$i++){
          $ip_begin=$ip_begin.$elements[$i].'.';
          $ip_end=$ip_end.$elements[$i].'.';
        }
        //echo "</br>--2----".(string)$ip_int;
        //print_r($ip_begin);
        $ip_begin=$ip_begin."".(string)(intval($elements[$ip_int]) & (~((1<<(8-$ip_rem))-1)));
        $ip_end=$ip_end."".(string)(intval($elements[$ip_int])|((1<<(8-$ip_rem))-1));
        if ($ip_int<3){
          for($i=$ip_int+1;$i<4;$i++){
            $ip_begin=$ip_begin.'.0';
            $ip_end=$ip_end.'.255';
          }
        }
        //echo "</br>--3----";
        //print_r($ip_begin);
        $result[]=$ip_begin;
        $result[]=$ip_end;
        return $result;
      }
      elseif(intval($ipn)==32){
        $result[]=$ip;
        $result[]=$ip;
        return $result;
      }
      else{
        $result[]='0.0.0.0';
        $result[]='0.0.0.0';
        return $result;
      }
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
              $result=array();
              if(isset($params->sort)){
                if ($_POST['search'] == 'ip'){
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  echo $ip_n;
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
                  $detail_count=0;
                  foreach($rows as $k=>$row)
                  {
                    //print_r($row);
                    //print_r("</br>");
                    $data=$row->content;
                    preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
                    if(count($ips)>1){
                      $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
                      $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
                      if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                        //unset($rows[$k]);
                        $result[$detail_count]=$row;
                        $detail_count++;
                      }
                    }
                  }
                  $rows=$result;
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
                  $detail_count=0;

                  foreach($rows as $k=>$row)
                  {
                    //print_r($row);
                    //print_r("</br>");
                    $data=$row->content;
                    preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
                    if(count($ips)>1){
                      $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
                      $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
                      if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                        //unset($rows[$k]);
                        $result[$detail_count]=$row;
                        $detail_count++;
                      }
                    }
                  }
                  $rows=$result;
                }
                else{
                  $rows = Whois::where('content', 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
                }
              }
              if ($_POST['search'] == 'ip'){
                $ip=$_POST['content'];
                $ip_n = bindec(decbin(ip2long($ip)));
                //$total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                $total=count($rows);
                if($total<=0){
                  //
                  WhoisController::query_now($ip);
                  //$ip_n = bindec(decbin(ip2long($ip)));
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->get();
                  $total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                }
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
    public function query_now($ip){
        $command="whois ".$ip;
        //$result=shell_exec($command);
        //echo ($command);
        exec($command,$arr);
        //print_r($arr);
        $data="";
        foreach ($arr as $key => $value) {
          if($value==''){
            $data=$data."\n";
          }
          if(substr($value,0,1)=="%" or substr($value,0,1)=="#"){
            continue;
          }
          if(substr($value,0,6)=="route:"){
            break;
          }
          $data=$data."\n".$value;
        }

        $data=preg_replace("/\n{3,}/","\n\n",$data);
        $data=preg_replace("/ {2,}/","",$data);
        $data=trim($data);

        preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ip);
        //print_r(count($ip));
        if(count($ip)>=3){
          $ip_begin=bindec(decbin(ip2long($ip[1])));
          $ip_end=bindec(decbin(ip2long($ip[2])));
          $hash=md5($data);
          //print_r($ip);
          $whois=new Whois;
          $whois->ip_begin=$ip_begin;
          $whois->ip_end=$ip_end;
          $whois->content=$data;
          $whois->hash=$hash;
          $whois->save();
        }else{
          //x.x.x.x/n
          preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
          if(count($ip)>=3){
            //print_r($ip);
            $ip1=ip_n_to_ip($ip[1],$ip[2]);
            $ip_begin=bindec(decbin(ip2long($ip1[1])));
            $ip_end=bindec(decbin(ip2long($ip1[2])));
            $hash=md5($data);
            $whois=new Whois;
            $whois->ip_begin=$ip_begin;
            $whois->ip_end=$ip_end;
            $whois->content=$data;
            $whois->hash=$hash;
            $whois->save();
            //print_r($ip1);
          }else{
            //x.x.x/n
            preg_match("/inetnum:(\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
            if(count($ip)>=3){
              //print_r($ip);
              $ip2=ip_n_to_ip($ip[1],$ip[2]);
              $ip_begin=bindec(decbin(ip2long($ip2[1])));
              $ip_end=bindec(decbin(ip2long($ip2[2])));
              $hash=md5($data);
              $whois=new Whois;
              $whois->ip_begin=$ip_begin;
              $whois->ip_end=$ip_end;
              $whois->content=$data;
              $whois->hash=$hash;
              $whois->save();
              //print_r($ip2);
            }else{
              //x.x/n
              preg_match("/inetnum:(\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
              if(count($ip)>=3){
                $ip3=ip_n_to_ip($ip[1],$ip[2]);
                $ip_begin=bindec(decbin(ip2long($ip3[1])));
                $ip_end=bindec(decbin(ip2long($ip3[2])));
                $hash=md5($data);
                $whois=new Whois;
                $whois->ip_begin=$ip_begin;
                $whois->ip_end=$ip_end;
                $whois->content=$data;
                $whois->hash=$hash;
                $whois->save();
                //print_r($ip3);
              }else{
                //print_r("no respect query data!");
              }
            }
          }
        }
    }
}
