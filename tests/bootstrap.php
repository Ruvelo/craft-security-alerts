<?php

declare(strict_types=1);

// Unit tests need Yii and Craft's helper classes, but no database and no Craft install.
// A bare console application is enough for validators, translation and events.

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/vendor/yiisoft/yii2/Yii.php';
require dirname(__DIR__) . '/vendor/craftcms/cms/src/Craft.php';

Craft::$app = new yii\console\Application([
    'id' => 'security-alerts-tests',
    'basePath' => dirname(__DIR__),
    'vendorPath' => dirname(__DIR__) . '/vendor',
    'components' => [
        // Craft registers a message source for every plugin's translation category. Stand in for it.
        'i18n' => [
            'translations' => [
                'security-alerts' => ['class' => yii\i18n\PhpMessageSource::class, 'basePath' => __DIR__ . '/_files/translations'],
            ],
        ],
    ],
]);
