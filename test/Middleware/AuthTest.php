<?php
namespace Xinix\BonoAuth\Test\Middleware;

use PHPUnit_Framework_TestCase;
use Xinix\BonoAuth\Middleware\Auth;
use Bono\App;
use Bono\Http\Uri;
use Bono\Http\Context;
use Bono\Http\Request;
use Bono\Http\Response;
use Bono\Exception\ContextException;
use Bono\Exception\BonoException;

class AuthTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->app = new App();
        $this->context = new Context($this->app, new Request(), new Response());
    }

    public function testIsAuthenticate()
    {
        $middleware = new Auth($this->app, [function() {}]);

        $context = $this->context;
        $this->assertEquals($middleware->isAuthenticate($context), false);
    }

    public function testInvoke()
    {
        $middleware = new Auth($this->app, [function() {}]);

        $context = $this->context;
        try {
            $hit = false;
            $context['@renderer'] = null;
            $context['@session'] = $this->getMock(\stdClass::class);
            $middleware->__invoke($context, function() use (&$hit) {
                $hit = true;
            });
            $this->fail('Must not here');
        } catch (BonoException $e) {
            if ($e->getMessage() !== 'Unregistered dependency @renderer middleware!') {
                throw $e;
            }
        }

        try {
            $hit = false;
            $context['@session'] = null;
            $context['@renderer'] = $this->getMock(\stdClass::class);
            $middleware->__invoke($context, function() use (&$hit) {
                $hit = true;
            });
            $this->fail('Must not here');
        } catch (BonoException $e) {
            if ($e->getMessage() !== 'Unregistered dependency @session middleware!') {
                throw $e;
            }
        }

        $hit = false;
        $context['@session'] = $this->getMock(\stdClass::class);
        $context['@renderer'] = $this->getMock(\stdClass::class);
        $middleware->__invoke($context, function() use (&$hit) {
            $hit = true;
        });

        $this->assertEquals($context['@auth'], $middleware);
        $this->assertEquals($hit, true);
    }

    public function testCallableRule()
    {
        $middleware = new Auth($this->app, [function() {}]);
        $middleware->clearRules();
        $middleware->addRule(function($context, $uri) {
            return $uri === '/foo';
        });

        $context = $this->context;
        $this->assertEquals(true, $middleware->authorize($context, '/foo'));
    }

    public function testAllowRejectRule()
    {
        $middleware = new Auth($this->app, [function() {}]);
        $middleware->clearRules();
        $middleware->addRule([ 'allow', '/foo', '*' ]);
        $middleware->addRule([ 'allow', '/foo/*', 'user:*' ]);
        $middleware->addRule([ 'allow', '/bar', '*' ]);
        $middleware->addRule([ 'allow', '/bar/*', 'user:foo' ]);
        $middleware->addRule([ 'allow', '/foox/**', '*' ]);
        $middleware->addRule([ 'reject' ]);

        $context = $this->context;
        $this->assertEquals(true, $middleware->authorize($context, '/foo'));
        $this->assertEquals(true, $middleware->authorize($context, '/bar'));
        $this->assertEquals(false, $middleware->authorize($context, '/baz'));
        $this->assertEquals(false, $middleware->authorize($context, '/foo/xxx'));
        $context['@session.data'] = ['auth' => ['$user' => ['foo']]];
        $this->assertEquals(true, $middleware->authorize($context, '/foo/xxx'));
        $this->assertEquals(true, $middleware->authorize($context, '/bar/xxx'));
        $context['@session.data'] = ['auth' => ['$user' => ['bar']]];
        $this->assertEquals(false, $middleware->authorize($context, '/bar/xxx'));

        $this->assertEquals(true, $middleware->authorize($context, (new Uri())->withPath('/foox/foo/bar')));

        try {
            $middleware->authorize($context, ['foo']);
            $this->fail('Must not here');
        } catch (\Exception $e) {
            if ($e->getMessage() !== 'Authorize 2nd parameter must be string or Bono\Http\Uri') {
                throw $e;
            }
        }

        try {
            $middleware->addRule([ 'unknown', '/baz', '*' ]);
            $this->fail('Must not here');
        } catch(\Exception $e) {
            if ($e->getMessage() !== 'Unknown behavior, must be value of allow or reject') {
                throw $e;
            }
        }

        try {
            $middleware->addRule([ 'allow', 123 ]);
            $this->fail('Must not here');
        } catch(\Exception $e) {
            if ($e->getMessage() !== 'Unknown evaluator, must be pattern string or callable') {
                throw $e;
            }
        }
    }

    public function testAuthenticate()
    {
        $middleware = new Auth($this->app, []);

        $context = $this->context;
        try {
            $middleware->authenticate($context);
            $this->fail('Must not here');
        } catch(\Exception $e) {
            if ($e->getMessage() !== 'Authenticator not found') {
                throw $e;
            }
        }

        $middleware->addAuthenticator(function($context) {
            $form = $context->getParsedBody();
            if (@$form['username'] === 'foo' && @$form['password'] === 'bar') {
                return [
                    'user' => [
                        'username' => 'foo',
                    ],
                ];
            }
        });

        $context->setParsedBody(['username' => 'foo', 'password' => 'bar']);
        $this->assertNotNull($middleware->authenticate($context));

        $context->setParsedBody(['username' => 'foo', 'password' => 'foo']);
        $this->assertNull($middleware->authenticate($context));
    }

    public function testLoginGet()
    {
        $middleware = new Auth($this->app, [function() { }]);
        $context = $this->context;
        $middleware->login($context);
        $this->assertEquals($context->getState(), ['entry' => []]);

        $middleware = new Auth($this->app, [function() { return false; }]);
        $context = $this->context;
        $middleware->login($context);
        $this->assertEquals($context->getState(), ['entry' => []]);
        $this->assertEquals($context->getStatusCode(), 400);

        $middleware = new Auth($this->app, [function() { return ['username' => 'foo']; }]);
        $context = $this->context;
        try {
            $middleware->login($context);
            $this->fail('Login failed');
        } catch(ContextException $e) {
            if (((int) ($e->getStatusCode() / 100)) !== 3) {
                $this->fail('Login failed #2');
            }
        }
    }

    public function testLoginPost()
    {
        $middleware = new Auth($this->app, [function($context) {
            $form = $context->getParsedBody();
            if ($form['username'] === 'foo' && $form['password'] === 'bar') {
                return [
                    'user' => $form,
                ];
            }
        }]);

        $context = $this->context;

        // fail
        $context->setMethod('POST')
            ->setParsedBody(['username' => 'foo', 'password' => 'baz']);
        $middleware->login($context);
        $this->assertEquals($context->getState(), ['entry' => [
            'username' => 'foo',
            'password' => 'baz',
        ]]);

        // success
        $context->setMethod('POST')
            ->setParsedBody(['username' => 'foo', 'password' => 'bar']);
        try {
            $middleware->login($context);
            $this->fail('Login failed');
        } catch(ContextException $e) {
            if (((int) ($e->getStatusCode() / 100)) !== 3) {
                $this->fail('Login failed #2');
            }
        }
    }

    public function testLogout()
    {
        $middleware = new Auth($this->app, [function($context) { }]);

        $context = $this->context;
        $session = $context['@session'] = $this->getMock(\stdClass::class, ['reset']);
        $session->expects($this->once())->method('reset');
        try {
            $middleware->logout($context);
            $this->fail('Logout failed');
        } catch(ContextException $e) {
            if (((int) ($e->getStatusCode() / 100)) !== 3) {
                $this->fail('Logout failed #2');
            }
        }
    }

    public function testContextMiddleware()
    {
        $middleware = new Auth($this->app, [function($context) { }]);
        $middleware->clearRules();
        $middleware->addRule(function($context, $uri) {
            return $uri === '/foo';
        });

        $context = $this->context;
        try {
            $middleware->contextMiddleware($context, function() { });
            $this->fail('Must not here');
        } catch(ContextException $e) {
            if (401 !== $e->getStatusCode()) {
                throw $e;
            }
        }

        $context['@session.data'] = ['auth' => []];
        try {
            $middleware->contextMiddleware($context, function() { });
            $this->fail('Must not here');
        } catch(ContextException $e) {
            if (403 !== $e->getStatusCode()) {
                throw $e;
            }
        }

        $context['original.uri'] = $context['original.uri']->withPath('/foo');
        $middleware->contextMiddleware($context, function() { });
    }
}