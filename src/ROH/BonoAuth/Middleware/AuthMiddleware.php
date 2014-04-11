<?php

namespace ROH\BonoAuth\Middleware;

use \Norm\Filter\Filter;
use \Norm\Filter\FilterException;

class AuthMiddleware extends \Slim\Middleware {
    protected $driver;

    public function call() {
        $app = $this->app;
        $request = $app->request;
        $response = $app->response;
        $that = $this;

        $defaultOptions = array(
            'unauthorizedUri' => '/unauthorized'
        );

        if (is_array($this->options)) {
            $this->options = array_merge($defaultOptions, $this->options);
        } else {
            $this->options = $defaultOptions;
        }

        if (!isset($this->options['class'])) {
            throw new \Exception('No auth driver specified.');
        }

        $Clazz = $this->options['class'];
        $app->auth = $driver = $this->driver = new $Clazz($this);

        if (!$driver instanceof \ROH\BonoAuth\Driver\Auth) {
            throw new \Exception('Auth driver should be instance of \\ROH\\BonoAuth\\Driver\\Auth.');
        }

        $pathInfo = $app->request->getPathInfo();

        // authentication needs SessionMiddleware
        if (!$app->has('\\Bono\\Middleware\\SessionMiddleware')) {
            throw new \Exception('Authentication need \\Bono\\Middleware\\SessionMiddleware.');
        }

        // theme may get templates from bono-auth
        $f = explode('/src/', __FILE__);
        $f = $f[0];
        $app->theme->addBaseDirectory($f);


        $app->filter('auth.html.link', function($l) use ($driver) {
            if ($driver->authorize($l['uri'])) {
                return '<a href="'.\URL::site($l['uri']).'">'.$l['label'].'</a>';
            }
        });

        $app->filter('auth.allowed', function($l) use ($driver) {
            return $driver->authorize($l);
        });

        $app->get('/unauthorized', function() use ($app, $response, $driver) {
            $app->flashNow('error', '<p>Unauthorized!</p>');
            $response->template('unauthorized');
        });

        $app->get('/login', function() use ($app, $response, $driver) {
            try {
                $loginUser = $driver->authenticate();

                if ($loginUser) {
                    $driver->redirectBack();
                }
            } catch(\Exception $e) {
                $app->flashNow('error', ''.$e);
            }

            $response->template('login');
        });


        $app->post('/login', function() use ($app, $driver) {
            $post = $app->request->post();


            $loginUser = $driver->authenticate(array(
                'username' => $post['username'],
                'password' => $post['password']
            ));

            if (!$loginUser) {
                $app->flashNow('error', 'Username or password not match.');
            }

            $app->response->template('login');
            $app->response->set('entry', $loginUser);
            $app->response->set('response', $app->response);

        });

        $app->get('/logout', function() use($app, $driver) {

            // $app->flash('info', 'Good bye.');

            $driver->revoke();

        });

        $app->get('/passwd', function() use ($app) {
            $app->response->template('passwd');
        });

        $app->post('/passwd', function() use ($app) {
            Filter::register('checkPassword', function($key, $value) {
                if ($_SESSION['user']['password'] === $value) {
                    return $value;
                } else {
                    throw FilterException::factory('Old password not valid')->name($key);
                }
            });

            $filter = Filter::create(array(
                'old' => 'trim|required|salt|checkPassword',
                'new' => 'trim|required|confirmed|salt',
            ));

            $app->response->template('passwd');

            $data = $filter->run($app->request->post());
            $errors = $filter->errors();
            if ($errors) {
                $err = new \Norm\Filter\FilterException();
                $err->sub($errors);
                $app->flashNow('error', ''.$err);
            } else {
                $user = \Norm::factory('User')->findOne($_SESSION['user']['$id']);

                $user['password'] = $data['new_confirmation'];
                $user['password_confirmation'] = $data['new_confirmation'];
                $user->save();

                $_SESSION['user'] = $user->toArray();
            }

            $app->response->set('entry', $data);

        });

        switch($app->request->getPathInfo()) {
            case '/login':
            case '/logout':
            case '/unauthorized':
                return $this->next->call();
        }

        if ($driver->authorize()) {
            return $this->next->call();
        } else {
            $response->redirect(\URL::create($this->options['unauthorizedUri'], array(
                'continue' => \URL::current()
            )));
        }

    }

}