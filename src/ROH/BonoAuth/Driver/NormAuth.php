<?php

namespace ROH\BonoAuth\Driver;

class NormAuth extends Auth {
    public function authenticate($username, $password) {

        if (is_null($username) && is_null($password)) {
            return null;
        }

        $users = \Norm\Norm::factory(@$this->options['userCollection'] ?: 'User');

        $user = $users->findOne(array('username' => $username));

        if (function_exists('salt')) {
            $password = salt($password);
        }

        if (is_null($user) || $user['password'] !== $password) {
            return null;
        }

        return $user->toArray();

    }

    public function authorize() {
        if (!empty($_SESSION['user'])) {
            return true;
        }
    }
}