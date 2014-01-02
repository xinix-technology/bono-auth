<?php

namespace ROH\BonoAuth\Middleware;

class AuthMiddleware extends \Slim\Middleware {
    public function call() {
        $config = $this->app->config('auth');

        $pathInfo = $this->app->request->getPathInfo();
        $app = $this->app;
        $request = $this->app->request;
        $response = $this->app->response;

        $this->app->get('/login', function() use ($response) {
            $this->app->response->template('login');
        });

        $this->app->post('/login', function() use ($request, $response) {
            $collection = \Norm\Norm::factory('User');

            $post = $this->app->request->post();
            $userModel = $collection->findOne(array('username' => $post['username']));

            if (isset($userModel) && $userModel->get('password') === $post['password']) {
                $_SESSION['user'] = $userModel->get('username');

                $response->redirect('/');
            } else {
                $this->app->flashNow('error', 'Username or password not match.');
                $this->app->response->template('login');
            }


        });

        $this->app->get('/logout', function() use($app, $response) {
            $app->session->restart();

            $app->flash('info', 'Good bye.');

            $response->redirect('/login');

        });

        $allow = false;
        $configAllow = $config['allow'];
        if (is_callable($config['allow'])) {
            $allow = $configAllow($this->app->request);
        } elseif (array_key_exists($pathInfo, $config['allow'])) {
            $allow = true;
        }

        if (!$allow && empty($_SESSION['user'])) {
            $this->app->response->redirect('/login');
        } else {
            $this->next->call();
        }

    }
}