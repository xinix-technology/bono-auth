<?php

namespace ROH\BonoAUth\Driver;

abstract class Auth {

    protected $middleware;

    protected $options;

    public function __construct($middleware) {
        $this->middleware = $middleware;
        $this->options = $this->middleware->options;
    }

    abstract public function authenticate($username, $password);

    abstract public function authorize();
}