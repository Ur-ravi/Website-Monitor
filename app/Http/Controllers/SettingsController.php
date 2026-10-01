<?php
namespace App\Http\Controllers;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\View\View;

class SettingsController extends Controller
{
    public function edit(): View { return view('settings.edit',['user'=>auth()->user()]); }
    public function update(Request $request): RedirectResponse
    {
        $data=$request->validate(['name'=>['required','string','max:255'],'email'=>['required','email','max:255','unique:users,email,'.auth()->id()],'current_password'=>['required','current_password'],'password'=>['required','string','min:10','confirmed']]);
        $u=auth()->user(); $u->name=$data['name']; $u->email=$data['email']; $u->password=Hash::make($data['password']); $u->save();
        return back()->with('success','Admin account updated successfully.');
    }
}
