<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;

class HomeController extends Controller
{
    // Handling GET request.
    public function index()
    {
        return view('home');
    }

    // Handling POST request.
    public function store(){
        if(isset($_POST)){
          if($_POST['type'] == 'init'){
            $links_first = DB::table('links')->min('first');
            $links_first = date('Y/m/d H:i:s', $links_first);
            $links_last = DB::table('links')->max('last');
            $links_last = date('Y/m/d H:i:s', $links_last);
            $links = array("first" => $links_first, "last" => $links_last);

            $monitors_first = DB::table('monitors')->min('first');
            $monitors_first = date('Y/m/d H:i:s', $monitors_first);
            $monitors_last = DB::table('monitors')->max('last');
            $monitors_last = date('Y/m/d H:i:s', $monitors_last);
            $monitors = array("first" => $monitors_first, "last" => $monitors_last);

            $origins_first = DB::table('origins')->min('first');
            $origins_first = date('Y/m/d H:i:s', $origins_first);
            $origins_last = DB::table('origins')->max('last');
            $origins_last = date('Y/m/d H:i:s', $origins_last);
            $origins = array("first" => $origins_first, "last" => $origins_last);

            $change = DB::table('changelog')->orderBy('date', 'desc')->first();
            $change->o_link = date('Y/m/d H:i:s', $change->o_link);
            $change->l_link = date('Y/m/d H:i:s', $change->l_link);
            $change->o_mon = date('Y/m/d H:i:s', $change->o_mon);
            $change->l_mon = date('Y/m/d H:i:s', $change->l_mon);
            $change->o_orig = date('Y/m/d H:i:s', $change->o_orig);
            $change->l_orig = date('Y/m/d H:i:s', $change->l_orig);
            $change->oldest = date('Y/m/d H:i:s', $change->oldest);
            $change->latest = date('Y/m/d H:i:s', $change->latest);

            $data = array("change" => $change);
            return $data;
          }
        }
    }
}
