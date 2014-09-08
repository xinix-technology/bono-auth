<?php

namespace ROH\BonoAuth;

class RequestWrapper
{
    protected $request;

    public function __construct($request)
    {
        $this->request = $request;
    }

    public function __call($method, $parameters)
    {
        return call_user_func_array(array($this->request, $method), $parameters);
    }

    public function getJSON()
    {
        return json_decode($this->request->getBody(true), true);
    }

    public function getString()
    {
        return $this->request->getBody(true);
    }
}
