<?php

namespace Xinix\BonoAuth\Middleware;

use Bono\App;
use Bono\Bundle;
use Bono\Http\Uri;
use Bono\Http\Context;
use Bono\Exception\BonoException;

class Auth
{
    protected $app;

    protected $rules = [];

    protected $authenticators = [];

    public function __construct(App $app, array $authenticators, array $rules = [])
    {
        $this->app = $app;

        $app->addBundle([
            'uri' => '/auth',
            'handler' => [ Bundle::class, [
                'options' => [
                    'routes' => [
                        [
                            'methods' => [ 'POST', 'GET' ],
                            'uri' => '/login',
                            'handler' => [ $this, 'login' ],
                        ],
                        [ 'uri' => '/logout', 'handler' => [ $this, 'logout' ], ],
                    ],
                ],
            ]]
        ]);

        foreach ($authenticators as $authenticator) {
            $this->addAuthenticator($authenticator);
        }

        array_unshift($rules, ['allow', '/auth/login', '*']);
        array_unshift($rules, ['allow', '/auth/logout', '*']);
        $rules[] = [ 'allow', '*', 'user:*' ];
        $rules[] = [ 'reject' ];

        foreach($rules as $rule) {
            $this->addRule($rule);
        }
    }

    public function addAuthenticator($authenticator)
    {
        $this->authenticators[] = $this->app->getInjector()->resolve($authenticator);
        return $this;
    }

    protected function isStatic($pattern)
    {
        return false === strpos($pattern, '*') ? true : false;
    }

    protected function isMatchCredential(Context $context, $credential)
    {
        if (is_bool($credential)) {
            return $credential;
        } else {
            @list($type, $values) = explode(':', $credential);
            $values = explode(',', $values);

            if ($this->isAuthenticate($context)) {
                if (in_array('*', $values)) {
                    return true;
                } elseif (isset($context['@session.data']['auth']['$'.$type])) {
                    $accepts = $context['@session.data']['auth']['$'.$type];
                    foreach ($values as $key => $value) {
                        if (is_array($accepts) && in_array($value, $accepts)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }

    public function isAuthenticate(Context $context)
    {
        return isset($context['@session.data']['auth']);
    }

    public function isMatchEvaluator($uri, $evaluator)
    {
        if (is_bool($evaluator)) {
            return $evaluator;
        } elseif (is_string($evaluator)) {
            return $uri === $evaluator;
        } else {
            $segments = explode('/', trim($uri, '/'));

            $count = count($segments);
            $index = 0;
            $result = true;


            foreach ($evaluator as $token) {
                if (isset($segments[$index])) {
                    if ('**' === $token) {
                        break;
                    } elseif ('*' === $token || $token === $segments[$index]) {
                        $index++;
                        continue;
                    }
                }

                $result = false;
                break;
            }
            return $result;
        }
    }

    public function stringToSegments($str)
    {
        return array_slice(explode('/', $str), 1);
    }

    public function clearRules()
    {
        $this->rules = [];
        return $this;
    }

    public function addRule($rule)
    {
        if (is_callable($rule)) {
            $this->rules[] = $rule;
        } elseif (is_array($rule)) {
            @list($behavior, $evaluator, $credential) = $rule;

            if (!in_array($behavior, ['allow', 'reject'])) {
                throw new BonoException('Unknown behavior, must be value of allow or reject');
            }

            if (null === $evaluator || '*' === $evaluator) {
                $evaluator = true;
            } elseif (is_string($evaluator)) {
                if (!$this->isStatic($evaluator)) {
                    $evaluator = $this->stringToSegments($evaluator);
                }
            } elseif (!is_callable($evaluator)) {
                throw new BonoException('Unknown evaluator, must be pattern string or callable');
            }

            if (null === $credential || '*' === $credential) {
                $credential = true;
            }

            $this->rules[] = function(Context $context, $uri) use ($behavior, $evaluator, $credential) {
                if (!$this->isMatchCredential($context, $credential)) {
                    return;
                } elseif (!$this->isMatchEvaluator($uri, $evaluator)) {
                    return;
                }

                return 'reject' === $behavior ? false : true;
            };
        }
    }

    public function __invoke(Context $context, callable $next)
    {
        $context->depends('@renderer', '@session');

        $context['@auth'] = $this;
        // $context['@renderer']->addTemplatePath(__DIR__.'/../../templates');

        $context->addMiddleware([$this, 'contextMiddleware']);

        $next($context);
    }

    public function contextMiddleware(Context $context, callable $next)
    {
        if ($this->authorize($context, $context['original.uri']->getPath())) {
            $next($context);
        } elseif (isset($context['@session.data']['auth'])) {
            $context->call('@notification', 'notify', [
                'level' => 'error',
                'message' => 'You are forbidden here. Back to <a href="'.$context->siteUrl().'">home</a>.',
            ]);
            return $context->throwError(403);
        } else {
            $context->call('@notification', 'notify', [
                'level' => 'error',
                'message' => 'You are not authorized. Please <a href="'. $context->siteUrl('/auth/login')
                    . '?!continue='.$context->getUri() .'">login</a>.',
            ]);
            return $context->throwError(401);
        }
    }

    public function authorize(Context $context, $uri)
    {
        if ($uri instanceof Uri) {
            $uri = $uri->getPath();
        } elseif (!is_string($uri)) {
            throw new BonoException('Authorize 2nd parameter must be string or Bono\Http\Uri');
        }
        $uri = rtrim($uri, '/') ?: '/';

        $answer = null;
        foreach ($this->rules as $rule) {
            $answer = $rule($context, $uri);
            if (is_bool($answer)) {
                break;
            }
        }

        return $answer;
    }

    public function authenticate(Context $context)
    {
        if (empty($this->authenticators)) {
            throw new BonoException('Authenticator not found');
        }

        foreach ($this->authenticators as $authenticator) {
            $result = $authenticator($context);
            if (null !== $result) {
                if (false !== $result) {
                    $context->call('@session', 'set', 'auth', $result);
                }
                return $result;
            }
        }
    }

    public function login(Context $context)
    {
        if ('POST' === $context->getMethod()) {
            $form = $context->getParsedBody();
            $context->setState('entry', $form);
            $credential = $this->authenticate($context);

            if (null === $credential || false === $credential) {
                $context->setStatus(400);
                $context->call('@notification', 'notify', [
                    'level' => 'error',
                    'message' => 'Username or password not match'
                ]);
            } else {
                $context->call('@notification', 'notify', [
                    'level' => 'info',
                    'message' => 'Welcome',
                ]);

                $context->back();
            }
        } else {
            $context->setState('entry', []);
            $credential = $this->authenticate($context);
            if (null !== $credential) {
                if (false === $credential) {
                    $context->setStatus(400);
                } else {
                    $context->back();
                }
            }
        }
    }

    public function logout(Context $context)
    {
        $context['@session']->reset($context);

        $context->call('@notification', 'notify', [
            'level' => 'info',
            'message' => 'You are now logout',
        ]);

        return $context->back();
    }
}