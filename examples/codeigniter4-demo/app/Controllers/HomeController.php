<?php

declare(strict_types=1);

namespace App\Controllers;

use CodeIgniter\HTTP\ResponseInterface;

class HomeController extends BaseController
{
    public function index(): string
    {
        return view('welcome_message');
    }

    public function login(): ResponseInterface|string
    {
        if ($this->request->getMethod() === 'post') {
            $username = $this->request->getPost('username');
            $password = $this->request->getPost('password');

            return $this->response->setJSON([
                'success' => true,
                'message' => 'Login attempt recorded',
                'username' => $username,
            ]);
        }

        return view('login_form');
    }

    public function apiUsers(): ResponseInterface
    {
        return $this->response->setJSON([
            'users' => [
                ['id' => 1, 'name' => 'John Doe'],
                ['id' => 2, 'name' => 'Jane Smith'],
            ],
        ]);
    }

    public function apiLogin(): ResponseInterface
    {
        $username = $this->request->getPost('username');
        $password = $this->request->getPost('password');

        return $this->response->setJSON([
            'success' => true,
            'token' => bin2hex(random_bytes(16)),
        ]);
    }
}
