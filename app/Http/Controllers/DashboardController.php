<?php
namespace App\Http\Controllers;

use App\Models\Website;
use App\Services\WebsiteMonitorService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

class DashboardController extends Controller
{
    public function index(Request $request): View
    {
        $status=$request->query('status'); $search=trim((string)$request->query('search')); $technology=$request->query('technology');
        $base=Website::query();
        $total=(clone $base)->count(); $up=(clone $base)->where('status','up')->count(); $down=(clone $base)->where('status','down')->count();
        $slow=(clone $base)->where('status','slow')->count(); $warning=(clone $base)->where('status','warning')->count(); $suspicious=(clone $base)->where('security_status','suspicious')->count(); $securityReview=(clone $base)->where('security_status','review')->count();
        $sslExpiring=(clone $base)->whereNotNull('ssl_expires_at')->whereBetween('ssl_expires_at',[now(),now()->copy()->addDays(30)])->count();
        $query=Website::query();
        if($request->query('security')==='review') $query->where('security_status','review'); elseif($status==='suspicious') $query->where('security_status','suspicious'); elseif($status) $query->where('status',$status); if($request->boolean('ssl')) $query->whereNotNull('ssl_expires_at')->whereBetween('ssl_expires_at',[now(),now()->copy()->addDays(30)]);
        if($search!=='') $query->where(fn($q)=>$q->where('name','like','%'.$search.'%')->orWhere('url','like','%'.$search.'%')->orWhere('technology','like','%'.$search.'%'));
        if($technology) $query->where('technology',$technology);
        $websites=$query->orderByRaw("CASE WHEN security_status='suspicious' THEN 0 WHEN status='down' THEN 1 WHEN status='warning' THEN 2 WHEN status='slow' THEN 3 ELSE 4 END")->latest()->paginate(25)->withQueryString();
        $problems=Website::query()->where('maintenance_mode',false)->where(function($q){
            $q->whereIn('status',['down','slow','warning'])->orWhereIn('security_status',['suspicious','review'])->orWhere(function($q2){$q2->whereNotNull('ssl_expires_at')->whereBetween('ssl_expires_at',[now(),now()->copy()->addDays(30)]);});
        })->orderByRaw("CASE WHEN security_status='suspicious' THEN 0 WHEN status='down' THEN 1 WHEN status='warning' THEN 2 WHEN status='slow' THEN 3 WHEN ssl_expires_at IS NOT NULL AND ssl_expires_at <= ? THEN 4 ELSE 5 END",[now()->addDays(30)])->latest('last_checked_at')->limit(12)->get();
        $technologies=Website::whereNotNull('technology')->where('technology','<>','')->distinct()->orderBy('technology')->pluck('technology');
        $technologyCounts = [
            'OJS' => (clone $base)->whereRaw('LOWER(technology) LIKE ?', ['%ojs%'])->count(),
            'PHP' => (clone $base)->whereRaw('LOWER(technology) LIKE ?', ['%php%'])->count(),
            'React' => (clone $base)->whereRaw('LOWER(technology) LIKE ?', ['%react%'])->count(),
        ];
        $monitorableIds = Website::where('is_active',true)->where('maintenance_mode',false)->orderBy('id')->pluck('id')->values();
        return view('dashboard.index',compact('websites','problems','total','up','down','slow','warning','suspicious','sslExpiring','securityReview','search','status','technology','technologies','technologyCounts','monitorableIds'));
    }

    public function checkAll(): \Illuminate\Http\JsonResponse
    {
        $ids=Website::where('is_active',true)->where('maintenance_mode',false)->orderBy('id')->pluck('id')->values();
        return response()->json(['ok'=>true,'count'=>$ids->count(),'website_ids'=>$ids,'message'=>'Use sequential browser checks to avoid long gateway requests.']);
    }
}
