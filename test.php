<?php

function ip_n_to_ip($ip,$ipn){
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
	echo "</br>--1---";
	print_r($elements);
	echo "</br>";
	print_r($ip);
	if (intval($ipn)<32 & intval($ipn)>0){
		#print ip_num[1]
		$ip_begin="";
		$ip_end="";
		$ip_int=floor(intval($ipn)/8);
		$ip_rem=intval($ipn)%8;
		for($i=0;$i<$ip_int;$i++){
			$ip_begin=$ip_begin.$elements[$i].'.';
			$ip_end=$ip_end.$elements[$i].'.';
		}
		echo "</br>--2----".(string)$ip_int;
		print_r($ip_begin);
		$ip_begin=$ip_begin."".(string)(intval($elements[$ip_int]) & (~((1<<(8-$ip_rem))-1)));
		$ip_end=$ip_end."".(string)(intval($elements[$ip_int])|((1<<(8-$ip_rem))-1));
		if ($ip_int<3){
			for($i=$ip_int+1;$i<4;$i++){
				$ip_begin=$ip_begin.'.0';
				$ip_end=$ip_end.'.255';
			}
		}
		echo "</br>--3----";
		print_r($ip_begin);
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
//phpinfo();
//$result=system("whois 202.118.236.100",$retval);
/*conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois*/
$command="whois 187.252.154.1";
//$result=shell_exec($command);
//print_r($result);
exec($command,$arr);
//print_r($arr);
$data="";
foreach ($arr as $key => $value) {
	# code...
	if($value==''){
		$data=$data."\n";
	}
	if($value[0]=="%"||$value[0]=="#"){
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
print_r(count($ip));
if(count($ip)>=3){
	$ip_begin=bindec(decbin(ip2long($ip[1])));
	$ip_end=bindec(decbin(ip2long($ip[2])));
	$hash=md5($data);
	print_r($ip);
	#my_mongo.insert({"ip_begin":$ip_begin,"ip_end":$ip_end,"content":$data,"hash":$hash})
}else{
	//x.x.x.x/n
	preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
	if(count($ip)>=3){
		print_r($ip);
		$ip1=ip_n_to_ip($ip[1],$ip[2]);
		$ip_begin=bindec(decbin(ip2long($ip1[1])));
		$ip_end=bindec(decbin(ip2long($ip1[2])));
		$hash=md5($data);
		print_r($ip1);
		#my_mongo.insert({"ip_begin":$ip_begin,"ip_end":$ip_end,"content":$data,"hash":$hash})
	}else{
		//x.x.x/n
		preg_match("/inetnum:(\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
		if(count($ip)>=3){
			print_r($ip);
			$ip2=ip_n_to_ip($ip[1],$ip[2]);
			$ip_begin=bindec(decbin(ip2long($ip2[1])));
			$ip_end=bindec(decbin(ip2long($ip2[2])));
			$hash=md5($data);
			print_r($ip2);
			#my_mongo.insert({"ip_begin":$ip_begin,"ip_end":$ip_end,"content":$data,"hash":$hash})
		}else{
			//x.x/n
			preg_match("/inetnum:(\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
			if(count($ip)>=3){
				$ip3=ip_n_to_ip($ip[1],$ip[2]);
				$ip_begin=bindec(decbin(ip2long($ip3[1])));
				$ip_end=bindec(decbin(ip2long($ip3[2])));
				$hash=md5($data);
				print_r($ip3);
				#my_mongo.insert({"ip_begin":$ip_begin,"ip_end":$ip_end,"content":$data,"hash":$hash})
			}else{
				print_r("no respect query data!");
			}
		}
	}
}
$json=array("content"=>$data);
$data=json_encode($json);

print_r($data);

$fp=fopen("liuyang.txt", "w");
if(!$fp){
	echo "system error";
	exit();
}else{
	echo strlen($data);
	fwrite($fp, $data);
	fclose($fp);
	//echo "success";
}
