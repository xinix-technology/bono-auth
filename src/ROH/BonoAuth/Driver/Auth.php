<?php

namespace ROH\BonoAUth\Driver;

use \Bono\Helper\URL;

abstract class Auth
{

    protected $middleware;

    protected $options;

    public function __construct($middleware)
    {
        $this->middleware = $middleware;
        $this->options = $this->middleware->options;
    }

    public function getRedirectUri()
    {
        return URL::redirect();
    }

    public function redirectBack()
    {
        \App::getInstance()->redirect($this->getRedirectUri());
    }

    abstract public function authenticate(array $options = array());

    abstract public function authorize($uri = '');

    abstract public function revoke();
}
