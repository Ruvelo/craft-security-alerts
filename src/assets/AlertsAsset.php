<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\assets;

use craft\web\AssetBundle;
use craft\web\assets\cp\CpAsset;

class AlertsAsset extends AssetBundle
{
    public function init(): void
    {
        $this->sourcePath = '@ruvelo/securityalerts/resources';
        $this->depends = [CpAsset::class];
        $this->css = ['alerts.css'];

        parent::init();
    }
}
