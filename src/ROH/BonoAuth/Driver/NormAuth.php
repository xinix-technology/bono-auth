<?php

namespace ROH\BonoAuth\Driver;

class NormAuth extends Auth
{
    public function authenticate(array $options = array())
    {
        $app = \App::getInstance();

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

        if (empty($options['keep'])) {
            $app->session->reset();
        } else {
            $app->session->reset(array(
                'lifetime' => 365 * 24 * 60 * 60
            ));
        }

        $_SESSION['user'] = $user;

        $app->redirect(\URL::redirect());

        return $user->toArray();

    }

    public function authorize($uri = '')
    {
        $authorized = f('auth.authorize', null);
        if (!is_null($authorized)) {
            return $authorized;
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
