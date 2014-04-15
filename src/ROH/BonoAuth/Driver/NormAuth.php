<?php

namespace ROH\BonoAuth\Driver;

class NormAuth extends Auth
{
    public function authenticate(array $options = array())
    {


        if (!isset($options['username']) && !isset($options['password'])) {
            return null;
        }

        $users = \Norm\Norm::factory(@$this->options['userCollection'] ?: 'User');

        $user = $users->findOne(array('username' => $options['username']));

        if (function_exists('salt')) {
            $options['password'] = salt($options['password']);
        }

        if (is_null($user) || $user['password'] !== $options['password']) {
            return null;
        }

        $_SESSION['user'] = $user;

        return $user->toArray();

    }

    public function authorize($uri = '')
    {
        if (f('auth.authorize', false)) {
            return true;
        }

        if (!empty($_SESSION['user'])) {
            return true;
        }
    }

    public function revoke()
    {
        $app = \App::getInstance();

        $app->session->reset();

        $app->redirect($this->options['unauthorizedUri']);
    }
}
