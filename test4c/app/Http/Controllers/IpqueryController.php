<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;

class IpqueryController extends Controller
{
    //
    public function index()
    {
        return view('ipquery');
    }

    public function store()
    {
        $type = $_POST['type'];
        if ($type == 'search'){
          $input = $_POST['input'];
          $result = array();
          $query = exec(app_path()."/Http/Controllers/client.py -i ".$input); 
          $sep = explode(": ", $query);
          if(strcmp($sep[1], "no result")){
            $str_len = strlen($sep[1]);
            $r_sep = explode(") (", substr($sep[1], 1, $str_len-2));
            //$r_count = count($r_sep);
            //$result["total"] = $r_count;
            foreach( $r_sep as $value){
              $rr_sep = explode(", ", $value);
              array_push($result, array("prefix"=> $rr_sep[0], "as"=> $rr_sep[1], "asname"=> $rr_sep[2]));
            }
            return $result;
          }
          else{
            return "noresult";
          }
        }
        else if ($type == 'prefix'){
          $input = $_POST['input'];
          return redirect('origins')->with('input', $input);
        }
    }
}
