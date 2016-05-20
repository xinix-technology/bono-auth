<?php
namespace Xinix\BonoAuth\Authenticator;

use Bono\App;
use ROH\Util\Options;
use Bono\Http\Context;

class Norm
{
    protected $app;

    protected $options;

    public function __construct(App $app, array $options = [])
    {
        $this->app = $app;

        $this->options = (new Options([
            'email' => 'email',
            'username' => 'username',
            'salted' => true,
            'normalizedUsername' => 'normalized_username',
        ]))->merge($options);
    }

    public function __invoke(Context $context)
    {
        $context->depends('@norm');

        if ('POST' === $context->getMethod()) {
            $body = $context->getParsedBody();

            $orQuery = [];
            if (false !== $this->options['username']) {
                $fieldName = is_string($this->options['username']) ? $this->options['username'] : 'username';
                $orQuery[] = [ $fieldName => @$body['username'], ];
            }
            if (false !== $this->options['email']) {
                $fieldName = is_string($this->options['email']) ? $this->options['email'] : 'email';
                $orQuery[] = [ $fieldName => @$body['email'], ];
            }
            if (false !== $this->options['normalizedUsername']) {
                $fieldName = is_string($this->options['normalizedUsername']) ? $this->options['normalizedUsername'] : 'normalizedUsername';
                $orQuery[] = [ $fieldName => @$body['normalizedUsername'], ];
            }

            $user = $context['@norm']->factory($context, 'User')->findOne([
                '!or' => $orQuery
            ]);

            $expectedPassword = $body['password'];
            if ($this->options['salted']) {
                $config = $context['@norm']->getRepository($context)->getAttribute('salt');
                if (null !== $config) {
                    $method = 'md5';
                    if (is_string($config)) {
                        $key = $config;
                    } elseif (2 === count($config)) {
                        list($method, $key) = $config;
                    }

                    if (!empty($key)) {
                        $expectedPassword = $method($expectedPassword.$key);
                    }
                }
            }

            if ((string) $user['password'] === $expectedPassword) {
                $userObject = $user->toArray();
                unset($userObject['password']);
                return [
                    'user' => $userObject,
                    'role' => isset($user['roles']) ? $user['roles'] : [],
                ];
            }
        }
    }
}