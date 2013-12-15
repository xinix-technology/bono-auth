<?php

namespace Reekoheek\BonoAuth\Middleware;

class AuthMiddleware extends \Slim\Middleware {
    public function call() {
        $app = $this->app;
        $request = $app->request;
        $response = $app->response;

        $config = $app->config('auth');

        $pathInfo = $request->getPathInfo();

        $app->get('/login', function() use ($app, $request, $response) {
            $response->template('login');
        });

        $app->post('/login', function() use ($app, $request, $response) {
            $collection = \Norm\Norm::factory('User');

            $post = $request->post();
            $userModel = $collection->findOne(array('username' => $post['username']));

            if (isset($userModel) && $userModel->get('password') === salt($post['password'])) {
                $_SESSION['user'] = $userModel;
                $response->redirect('/');
            } else {
                $app->flashNow('error', 'Username or password not match.');
                $response->template('login');
            }

        });

        $app->get('/logout', function() use ($app, $request, $response) {
            $app->session->restart();

            $app->flash('info', 'Good bye.');

            $response->redirect('/login');
        });

        $allow = false;
        if (array_key_exists($pathInfo, $config['allow'])) {
            $allow = true;
        }

        if (!$allow && empty($_SESSION['user'])) {
            $response->redirect('/login');
        } else {
            $this->next->call();
        }

    }
}