<?php

namespace Xinix\BonoAuth\Observer;

class NormalizeUsername
{
    public function saving($model)
    {
        if ($model->isNew()) {
            $model['normalized_username'] = str_replace('.', '', $model['username']);
            $existingUser = \Norm::factory('User')->findOne(array(
                'normalized_username' => $model['normalized_username']
            ));

            if ($existingUser) {
                throw new \Exception('Username apparently already exists');
            }
        }
    }
}
