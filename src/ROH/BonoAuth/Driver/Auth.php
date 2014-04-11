<?php

namespace ROH\BonoAUth\Driver;

abstract class Auth {

    protected $middleware;

    protected $options;

    public function __construct($middleware) {
        $this->middleware = $middleware;
        $this->options = $this->middleware->options;
    }

    public function redirectBack() {
        $continue = @$_GET['continue'] ?: '/';
        \App::getInstance()->redirect($continue);
    }

    abstract public function authenticate(array $options = array());

    abstract public function authorize($uri = '');

    abstract public function revoke();
}