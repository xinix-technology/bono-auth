bono-auth
=========

Your solution to use authorization and authentication with Bono Framework.

# Setup

To use bono-auth you have to setup bono using bono-auth middleware in config.php.

```php
'bono.middlewares' => array(
  '\\ROH\\BonoAuth\\Middleware\\AuthMiddleware' => array(
    ...
  ),
),
```


bono-auth has two drivers to use, each will have distinct configuration:

## ROH\BonoAuth\Driver\NormAuth

```php
'bono.middlewares' => array(
  '\\ROH\\BonoAuth\\Middleware\\AuthMiddleware' => array(
    'driver' => '\\ROH\\BonoAuth\\Driver\\NormAuth'
  ),
),
```

## ROH\BonoAuth\Driver\OAuth

```php
'bono.middlewares' => array(
  '\\ROH\\BonoAuth\\Middleware\\AuthMiddleware' => array(
    'driver' => '\\ROH\\BonoAuth\\Driver\\OAuth',
    'debug' => true, // enable or disable debug
    'baseUrl' => 'http://to.your.oauth.provider',
    'authUrl' => '/oauth/auth', // URI to access auth
    'tokenUrl' => '/oauth/token', // URI to get token
    'revokeUrl' => '/oauth/revoke', // URI to revoke auth
    'clientId' => '*the client id*',
    'clientSecret' => '*the client secret*',
    'redirectUri' => \Bono\Helper\URL::site('/login'), // application redirect url
    'scope' => 'user',
  ),
),
```

Above configuration will enable default bono-auth. The default value will prevent guest to access to every pages 
accessed. And after user get login, he will be able to access every pages available.

# Authorization

To authorize/deauthorize specific pages, you have to write codes to register filter "auth.authorize" that run before the middleware invoked by system. Usually you can put this codes in provider file. The codes will be in this following form:

```php
$app->filter('auth.authorize', function ($options) {
  // something to do
  return $allowed;
});
```
## Return value

If the return value will be the one of the following conditions:
- True (bool), url is authorized
- False (bool), url is not authorized
- (original argument), bono-auth will decide authorization for you, the default is logined user authorize to access and guest user is not authorized

## Arguments

The filter will accept single argument $options. As the nature of Bono Filter, the $options will be return value of previous ran of the same context name function. The first time value of $options will be the URI string (or assoc array contains URI string). 

If the $options is_bool, it means one of previous filter functions already handle the URI, you can skip the current filter function by adding if-statement.

```php
$app->filter('auth.authorize', function ($options) {
  if (is_bool($options)) {
    return $options;
  }
  // something to do
});
```

