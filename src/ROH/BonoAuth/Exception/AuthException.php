<?php

namespace ROH\BonoAuth\Exception;

class AuthException extends \Exception
{
    public static $MESSAGE_CODES = array(
        'access_denied' => 'Access denied',
        'client_denied' => 'Client denied',
    );

    protected $messageCode;

    public function __construct($message = null)
    {

        $this->messageCode = $message;
        $message = @static::$MESSAGE_CODES[$message] ?: $message;
        parent::__construct($message);
    }
}
