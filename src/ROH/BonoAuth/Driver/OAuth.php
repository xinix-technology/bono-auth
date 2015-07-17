<?php

namespace ROH\BonoAuth\Driver;

use Bono\App;
use Guzzle\Service\Client as GuzzleClient;
use ROH\BonoAuth\RequestWrapper;
use Norm\Filter\FilterException;
use Exception;
use Slim\Exception\Stop;

class OAuth extends NormAuth
{
    protected $client = null;

    protected $token = null;

    public function authenticate(array $options = array())
    {
        $app = App::getInstance();

        try {
            if (!empty($_GET['error'])) {
                throw new Exception($_GET['error']);
            }

            if (empty($_GET['code'])) {
                $url = \URL::create($this->options['authUrl'], array(
                    'response_type' => 'code',
                    'client_id' => $this->options['clientId'],
                    'redirect_uri' => $this->options['redirectUri'],
                    'scope' => @$this->options['scope'],
                    'state' => '',
                    // 'access_type' => 'online',
                    // 'approval_prompt' => 'auto',
                    // 'login_hint' => '',
                    // 'include_granted_scopes' => true
                ), $this->options['baseUrl']);
                return \App::getInstance()->redirect($url);
            } else {
                if (empty($_GET['keep'])) {
                    $app->session->reset();
                } else {
                    $app->session->reset(array(
                        'lifetime' => 365 * 24 * 60 * 60
                    ));
                }

                $this->exchangeCodeForToken($_GET['code']);

                $me = $this->fetchRemoteUser();

                $user = $this->authenticateRemoteUser($me);


                $_SESSION['user'] = $user;

                return $user;
            }
        } catch (Stop $e) {
            return;
        } catch (Exception $e) {
            if ($e instanceof \Norm\Filter\FilterException) {
                $error = 'Caught filter error! Please contact Administrator';
            } else {
                $error = $e->getMessage();
            }
            $url = \URL::create($this->options['unauthorizedUri'], array('error' => $error));
            return \App::getInstance()->redirect($url);
        }
    }

    public function revoke()
    {
        try {
            $this->get('/oauth/revoke')->getBody(true);
        } catch (\Exception $e) {
        }
        parent::revoke();
    }

    public function fetchRemoteUser()
    {

        $userUrl = (empty($this->options['userUrl'])) ? '/home/user/me' : $this->options['userUrl'];
        $json = $this->get($userUrl)->getJSON();
        return $json['entry'];
    }

    public function authenticateRemoteUser($remoteUser)
    {
        $app = \App::getInstance();

        $authorized = f('auth.remoteAuthorize', $remoteUser);

        if ($authorized) {
            $users = \Norm\Norm::factory('User');

            $user = $users->findOne(array('username' => $remoteUser['username']));

            if (is_null($user)) {
                $user = $users->newInstance();
                $user['username'] = $remoteUser['username'];
                $user['first_name'] = $remoteUser['first_name'];
                $user['last_name'] = $remoteUser['last_name'];
                $user['birth_date'] = $remoteUser['birth_date'];
                $user['birth_place'] = $remoteUser['birth_place'];
            }

            if (!empty($remoteUser['normalized_username'])) {

                $user['normalized_username'] = $remoteUser['normalized_username'];
            }
            $user['email'] = $remoteUser['email'];
            $user['sso_account_id'] = $remoteUser['$id'];
            $user->save();
        } else {
            throw new \Exception('You are unauthorized to access this application. Please contact administrator.');
        }

        return $user->toArray();

    }

    public function exchangeCodeForToken($code)
    {
        try {
            $params = array(
                'code' => $code,
                'client_id' => $this->options['clientId'],
                'client_secret' => $this->options['clientSecret'],
                'redirect_uri' => $this->options['redirectUri'],
                'grant_type' => 'authorization_code',
            );

            $request = $this->post($this->options['tokenUrl'], $params);

            $content = $request->getJSON();

            $content['expires'] = new \DateTime($content['expires']);

            $_SESSION['auth.token'] = $this->token = $content;

            return $content;
        } catch (\Guzzle\Http\Exception\BadResponseException $e) {
            return \App::getInstance()->redirect(
                $this->options['unauthorizedUri'].'?error='.
                preg_replace('/\s+/', ' ', $e->getMessage())
            );
        } catch(\Exception $e) {
            return \App::getInstance()->redirect(
                $this->options['unauthorizedUri'].'?error='.
                preg_replace('/\s+/', ' ', $e->getMessage())
            );
        }
    }

    public function getAccessToken()
    {
        if (is_null($this->token) && isset($_SESSION['auth.token'])) {
            $this->token = $_SESSION['auth.token'];
        }

        // FIXME if expired go logout or refresh token
        if (isset($this->token['access_token'])) {
            return $this->token['access_token'];
        }
    }

    public function getClient()
    {
        if (is_null($this->client)) {
            $this->client = new GuzzleClient();
            if (empty($this->options['debug'])) {
                $this->client->setSslVerification(false, false);
            }
        }
        return $this->client;
    }

    public function post($uri, $params = null)
    {
        $url = \URL::create($uri, null, $this->options['baseUrl']);
        return new RequestWrapper($this->getClient()->post($url, $this->getDefaultHeaders(), $params)->send());
    }

    public function get($uri, $params = null)
    {
        $url = \URL::create($uri, $params, $this->options['baseUrl']);

        return new RequestWrapper($this->getClient()->get($url, $this->getDefaultHeaders())->send());
    }

    public function getDefaultHeaders()
    {
        $token = $this->getAccessToken();

        $headers = null;
        if (isset($token)) {
            $headers = array(
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer '.$token,

            );
        }
        return $headers;
    }
}
