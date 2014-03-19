<?php

namespace ROH\BonoAuth\Driver;

class OAuth extends Auth {
    public function authenticate($username, $password) {
        if (!empty($_GET['error'])) {
            throw new \Exception($_GET['error']);
        }

        if (empty($_GET['code'])) {
            $url = \URL::create($this->options['url'], array(
                'response_type' => 'code',
                'client_id' => $this->options['clientId'],
                'redirect_uri' => $this->options['redirectUri'],
                'scope' => @$this->options['scope'],
                'state' => '',
                // 'access_type' => 'online',
                // 'approval_prompt' => 'auto',
                // 'login_hint' => '',
                // 'include_granted_scopes' => true
            ));
            return \App::getInstance()->redirect($url);
        } else {
            var_dump(\App::getInstance()->auth);
            var_dump($_GET['code']);
        }
    }

    public function authorize() {
        var_dump('expression');
    }
}