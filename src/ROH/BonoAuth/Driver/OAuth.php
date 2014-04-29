<?php

namespace ROH\BonoAuth\Driver;

use Bono\App;
use Guzzle\Service\Client as GuzzleClient;
use ROH\BonoAuth\RequestWrapper;

class OAuth extends NormAuth
{
    protected $client = null;
    protected $token = null;

    public function authenticate(array $options = array())
    {
        if (!empty($_GET['error'])) {
            $url = \URL::create($this->options['unauthorizedUri'], \App::getInstance()->request->get());
            return \App::getInstance()->redirect($url);
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
            $this->exchangeCodeForToken($_GET['code']);

            $me = $this->fetchRemoteUser();

            $user = $this->authenticateRemoteUser($me);

            $_SESSION['user'] = $user;

            return $user;
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
        $json = $this->get('/user/me')->getJSON();
        return $json['entry'];
    }

    public function authenticateRemoteUser($remoteUser)
    {
        $users = \Norm\Norm::factory('User');

        $user = $users->findOne(array('sso_account_id' => $remoteUser['$id']));


        if (is_null($user)) {

            // try {

            $user = $users->newInstance();
            $user['username'] = $remoteUser['username'];
            $user['first_name'] = $remoteUser['first_name'];
            $user['last_name'] = $remoteUser['last_name'];
            $user['email'] = $remoteUser['email'];
            $user['birth_date'] = $remoteUser['birth_date'];
            $user['birth_place'] = $remoteUser['birth_place'];
            $user['sso_account_id'] = $remoteUser['$id'];
            $user->save();

            // } catch(\Exception $e) {

            // }

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
            if ($this->options['debug']) {
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
