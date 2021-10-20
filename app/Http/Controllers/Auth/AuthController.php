<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    public function signup(Request $request)
    {   
        if(empty($request->email) || empty($request->password) || empty($request->name) || empty($request->last_name)){
            return response()->json('FAIL', 200);
        }
        $body = $request->validate([
            'name' => 'required|string',
            'last_name' => 'required|string',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);
        $body['password'] = Hash::make($body['password']);

        $user = User::create($body);

        $token = $user->createToken("$user->id-token-" . uniqid())->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response()->json($response, 201);
    }

    public function test(){
        return 'FUNCIONA';
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response('LOGGED OUT');
    }

    public function login(Request $request)
    {
        $body = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        if (!Auth::attempt($body)) {
            // return response()->json([
            //     'data' => 'BAD CREDENTIALS',
            // ], 401);
            return response('BAD CREDENTIALS');
        }

        $user = Auth::user();

        $token = $user->createToken("$user->id-token-" . uniqid())->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response()->json($response, 201);
    }

    public function getUser(Request $request)
    {
        return $request->user();
    }
}
