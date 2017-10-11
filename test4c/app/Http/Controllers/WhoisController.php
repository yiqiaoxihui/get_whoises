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
    public function whois_file_json_array(){
      $fpw=fopen("/data/3689ip_json_2.txt", "w");
      $fp=fopen("/data/all_ip.txt", "r");
      $ip_array=array();
      $i=0;
      while(!feof($fp)){
        $ip_array[$i]=fgets($fp);
        $$ip_array[$i]=trim($$ip_array[$i]);
        $i++;
      }
      fclose($fp);
      $ip_array=array_filter($ip_array);
      foreach ($ip_array as $ip) {
        $json="";
        $result=array();
        $main_content_array_k_v=array();
        $main_content_array_k_v['ip']=$ip;
        if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
        {
          $ip_n = bindec(decbin(ip2long($ip)));
          $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
          if(count($rows)<=0){
            $main_content_array_k_v['whois']="";
            $json= json_encode($main_content_array_k_v);
            fwrite($fpw, $json);
            fwrite($fpw, "\n");
            continue;
          }
          $i=0;
          //init the distance
          $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
          $result['ip_begin']=$rows[0]['ip_begin'];
          $result['ip_end']=$rows[0]['ip_end'];
          $result['content']=$rows[0]['content'];
          foreach ($rows as $row) {
            if(($row['ip_end']-$row['ip_begin'])<$last_distance)
            {
              //choose the most accurate one
              $last_distance=$row['ip_end']-$row['ip_begin'];
              $result['ip_begin']=$row['ip_begin'];
              $result['ip_end']=$row['ip_end'];
              $result['content']=$row['content'];
            }
            $data=$row->content;
            preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
            if(count($ips)>1){
              $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
              $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
              if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                //choose the most accurate one
                if(($ip_end-$ip_begin)<$last_distance){
                  $second=1;
                  $ip_range=$ips[count($ips)-1][0];
                  $last_distance=$ip_end-$ip_begin;
                  $result['ip_begin']=$row['ip_begin'];
                  $result['ip_end']=$row['ip_end'];
                  $result['content']=$row['content'];
                }
              }

            }
          }
          $content=$result['content'];
          $object_items=array();
          $main_content="";
          $object_items=explode("\n\n",$content);
          foreach ($object_items as $object_item) 
          {
            if((strpos($object_item, "NetRange")!==false) || (strpos($object_item, "inetnum")!==false))
            {
              $main_content=$object_item;
            }
          }
          $main_content_array=explode("\n", $main_content);
          $attr_item=array();
          $i=0;
          $j=0;
          $useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
          foreach ($main_content_array as $value) {
            $attr_item=explode(":", $value);
            if(count($attr_item)<2){
              continue;
            }
            if($attr_item[0]=="descr"){
              $main_content_array_k_v["whois"]["descr"][$i++]=$attr_item[1];
              //$item[0]="descr".$i++;
            }elseif($attr_item[0]=="remarks"){
              $main_content_array_k_v["whois"]["remarks"][$j++]=$attr_item[1];
              //$item[0]="descr".$i++;
            }else{
              $main_content_array_k_v["whois"][$attr_item[0]]=$attr_item[1];
            }
          }
          $date1="20170901-23:13:00";
          $main_content_array_k_v["whois"]["timestamp"]=$date1;
          $json= json_encode($main_content_array_k_v);
        }else{
          $main_content_array_k_v["whois"]="";
          $json= json_encode($main_content_array_k_v);
        }
        fwrite($fpw, $json);
        fwrite($fpw, "\n");
      }
      fclose($fpw);
      print_r("completed!");
    }

    public function whois_file_json_line(){
      $fpw=fopen("/data/3689ip_json_3.txt", "w");
      $fp=fopen("/data/all_ip.txt", "r");
      $ip_array=array();   
      $i=0;
      while(!feof($fp)){
        $ip_array[$i]=fgets($fp);
        $ip_array[$i]=trim($ip_array[$i]);
        $i++;
      }
      fclose($fp);
      $ip_array=array_filter($ip_array);
      foreach ($ip_array as $ip) {
        $json="";
        $result=array();
        $result[$ip]["whois"]="";
        if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
        {
          $ip_n = bindec(decbin(ip2long($ip)));
          $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
          if(count($rows)<=0){
            $json= json_encode($result);
            fwrite($fpw, $json);
            fwrite($fpw, "\n");
            continue;
          }
          $i=0;
          //init the distance
          $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
          $result['ip_begin']=$rows[0]['ip_begin'];
          $result['ip_end']=$rows[0]['ip_end'];
          $result['content']=$rows[0]['content'];
          foreach ($rows as $row) {
            if(($row['ip_end']-$row['ip_begin'])<$last_distance)
            {
              //choose the most accurate one
              $last_distance=$row['ip_end']-$row['ip_begin'];
              $result['ip_begin']=$row['ip_begin'];
              $result['ip_end']=$row['ip_end'];
              $result['content']=$row['content'];
            }
          }
          $second=0;
          $ip_range="";
          foreach($rows as $row)
          {
            $data=$row->content;
            preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
            if(count($ips)>1){
              //print_r(count($ips));
              //print_r($ips[count($ips)-1][1]);
              $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
              $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
              if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                //choose the most accurate one
                if(($ip_end-$ip_begin)<$last_distance){
                  $second=1;
                  $ip_range=$ips[count($ips)-1][0];
                  $last_distance=$ip_end-$ip_begin;
                  $result['ip_begin']=$row['ip_begin'];
                  $result['ip_end']=$row['ip_end'];
                  $result['content']=$row['content'];
                }
              }
            }
          }
          $content=$result['content'];
          $items=array();
          $main_content="";
          $items=explode("\n\n",$content);
          foreach ($items as $key => $item) 
          {
            if((strpos($item, "NetRange")!==false) || (strpos($item, "inetnum")!==false))
            {
              $main_content=$item;
            }
          }
          $main_content_array=explode("\n", $main_content);
          $main_content_array_k_v=array();
          $item=array();
          $i=0;
          $useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
          foreach ($main_content_array as $value) {
            $item=explode(":", $value);
            if(count($item)<2){
              continue;
            }
            if($item[0]=="descr"){
              $main_content_array_k_v[$ip]["whois"]["descr"][$i++]=$item[1];
              //$item[0]="descr".$i++;
            }else{
              $main_content_array_k_v[$ip]["whois"][$item[0]]=$item[1];
            }
          }
          $date1="20170901-23:13:00";
          $main_content_array_k_v[$ip]["whois"]["timestamp"]=$date1;
          $json= json_encode($main_content_array_k_v);
        }else{
          $json= json_encode($result);
        }
        fwrite($fpw, $json);
        fwrite($fpw, "\n");
      }
      fclose($fpw);
      print_r("completed!");
    }
    public function whois_api(Request $request){
      $ip=$request->ip;
      $result=array();
      $main_content_array_k_v=array();
      $main_content_array_k_v["ip"]=$ip;
      //input is right ip
      if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
      {
        $ip_n = bindec(decbin(ip2long($ip)));
        $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
        if(count($rows)<=0){
          $main_content_array_k_v["whois"]="";
          return json_encode($result);
        }
        $i=0;
        //init the distance
        $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
        $result['ip_begin']=$rows[0]['ip_begin'];
        $result['ip_end']=$rows[0]['ip_end'];
        $result['content']=$rows[0]['content'];
        foreach ($rows as $key => $row) {
          if(($row['ip_end']-$row['ip_begin'])<$last_distance)
          {
            //choose the most accurate one
            $last_distance=$row['ip_end']-$row['ip_begin'];
            $result['ip_begin']=$row['ip_begin'];
            $result['ip_end']=$row['ip_end'];
            $result['content']=$row['content'];
          }
        }
/*        $second=0;
        $ip_range="";
        foreach($rows as $k=>$row)
        {
          $data=$row->content;
          preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
          if(count($ips)>1){
            $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
            $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
            if($ip_n>=$ip_begin && $ip_n<=$ip_end){
              //choose the most accurate one
              if(($ip_end-$ip_begin)<$last_distance){
                $second=1;
                $ip_range=$ips[count($ips)-1][0];
                $last_distance=$ip_end-$ip_begin;
                $result['ip_begin']=$row['ip_begin'];
                $result['ip_end']=$row['ip_end'];
                $result['content']=$row['content'];
              }
              //$result[$i]=$row;
              //$i++;
            }

          }
        }*/
        $content=$result['content'];
        $items=array();
        $main_content="";
        $items=explode("\n\n",$content);
        foreach ($items as $key => $item) 
        {
          if((strpos($item, "NetRange")!==false) || (strpos($item, "inetnum")!==false))
          {
            $main_content=$item;
          }
        }
        $main_content_array=explode("\n", $main_content);
        $item=array();
        $i=0;
        $j=0;
        //$useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
        foreach ($main_content_array as $key => $value) {
          $item=explode(":", $value);
          if(count($item)<2){
            continue;
          }
          if($item[0]=="descr"){
            $main_content_array_k_v["whois"]["descr"][$i++]=$item[1];
            //$item[0]="descr".$i++;
          }elseif($item[0]=="remarks"){
            $main_content_array_k_v["whois"]["remarks"][$j++]=$item[1];

          }else{
            $main_content_array_k_v["whois"][$item[0]]=$item[1];
          }
        }
        //print_r($main_content_array_k_v["whois"]["remarks"]);
        $date1="20170901-23:13:00";
        $main_content_array_k_v["whois"]["timestamp"]=$date1;
        return json_encode($main_content_array_k_v);
      }else{
        $main_content_array_k_v["whois"]="";
        return json_encode($result);
      }
    }
    public function whois_test($ip,$params){
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
        return $result;
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
    public function get_detail_one($rows){
        $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
        $result=array();
        $result[0]=$rows[0];
        foreach ($rows as $key => $row) {
          if(($row['ip_end']-$row['ip_begin'])<$last_distance)
          {
            //choose the most accurate one
            $last_distance=$row['ip_end']-$row['ip_begin'];
            $result[0]=$row;
          }
        }
        return $result;
    }
    public function store()
    {
        $total=0;
        $detail_count=0;
        
        if(isset($_POST['from'])){
          return view('origins', ['input' => $_POST['content']]);
        }
        else{
          if($_POST['type'] == 'data'){
            $params = json_decode($_POST['data']);
            if(strlen($_POST['content']) > 0)
            {
              if(isset($params->sort))
              {
                if ($_POST['search'] == 'ip')
                {
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  //echo $ip_n;
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->orderBy($params->sort, $params->order)->get();
                  if(count($rows)>0){
                    $rows=WhoisController::get_detail_one($rows);
                  }
                  $total=count($rows);
                  //$rows=array_slice($result,$params->offset,$params->limit);
                }else{
                  $rows = Whois::where('content', 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
                  $total = Whois::where('content', 'like', '%'.$_POST['content'].'%')->count();
                }
              }
              else{//not isset($params->sort
                if($_POST['search'] == 'ip'){
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
                  if(count($rows)>0){
                    $rows=WhoisController::get_detail_one($rows);

                  }
                  $total=count($rows);
/*                  $result=array();
                  $detail_count=0;
                  foreach($rows as $row)
                  {
                    $data=$row->content;
                    preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
                    if(count($ips)>1){
                      $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
                      $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
                      if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                          $result[$detail_count]=$row;
                          $detail_count++;
                      }
                    }
                  }
                  $total=count($result);
                  $rows=array_slice($result,$params->offset,$params->limit);*/
                }else{
                  $rows = Whois::where('content', 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
                  $total = Whois::where('content', 'like', '%'.$_POST['content'].'%')->count();
                }
              }
              if ($_POST['search'] == 'ip'){
                //$total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                if($total<=0){
                  //WhoisController::query_now($ip);
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->get();
                  $total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                }
              }
            }
            else{//all
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
          $data=$data."\n".$value;
        }

        $data=preg_replace("/\n{3,}/","\n\n",$data);
        $data=preg_replace("/ {2,}/"," ",$data);
        $data=trim($data);
        $position=strpos($data, "Found a referral to");
        if($position>0){
          $position=strpos($data, "inetnum",$position);
          if($position>0)
            $data=substr($data, $position);
        }
        preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ip);
        //print_r(count($ip));
        if(count($ip)>=3){
          $ip_begin=bindec(decbin(ip2long($ip[1])));
          $ip_end=bindec(decbin(ip2long($ip[2])));
          $ip_range_str=$ip[1].$ip[2];
          $hash=md5($ip_range_str);
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
            $ip_range_str=$ip1[1].$ip1[2];
            $hash=md5($ip_range_str);
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
              $ip_range_str=$ip2[1].$ip2[2];
              $hash=md5($ip_range_str);
              $ip_begin=bindec(decbin(ip2long($ip2[1])));
              $ip_end=bindec(decbin(ip2long($ip2[2])));
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
                $ip_range_str=$ip3[1].$ip3[2];
                $hash=md5($ip_range_str);
                $ip_begin=bindec(decbin(ip2long($ip3[1])));
                $ip_end=bindec(decbin(ip2long($ip3[2])));
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
