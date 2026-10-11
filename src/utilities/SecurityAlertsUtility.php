<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\utilities;

use Craft;
use craft\base\Utility;
use DateTime;
use DateTimeZone;
use ruvelo\securityalerts\assets\AlertsAsset;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\Plugin;
use ruvelo\securityalerts\services\Checker;
use ruvelo\securityalerts\services\FindingStore;
use ruvelo\securityalerts\services\State;

/**
 * Utilities → Security alerts.
 */
class SecurityAlertsUtility extends Utility
{
    public static function displayName(): string
    {
        return Craft::t('security-alerts', 'Security alerts');
    }

    public static function id(): string
    {
        return 'security-alerts';
    }

    public static function icon(): ?string
    {
        return Craft::getAlias('@ruvelo/securityalerts/icon-mask.svg');
    }

    public static function badgeCount(): int
    {
        if (!Craft::$app->getUser()->checkPermission(Plugin::PERMISSION_VIEW)) {
            return 0;
        }

        return Findings::exploitedCount((new FindingStore())->all());
    }

    public static function contentHtml(): string
    {
        $view = Craft::$app->getView();
        $view->registerAssetBundle(AlertsAsset::class);

        if (!Craft::$app->getUser()->checkPermission(Plugin::PERMISSION_VIEW)) {
            return $view->renderTemplate('security-alerts/_denied');
        }

        $lastCheck = (new State())->get(Checker::STATE_LAST_CHECK);

        return $view->renderTemplate('security-alerts/_utility', [
            'findings' => Findings::sorted((new FindingStore())->all()),
            'lastCheck' => $lastCheck !== null ? new DateTime($lastCheck, new DateTimeZone('UTC')) : null,
            'settings' => Plugin::getInstance()?->getSettings(),
        ]);
    }
}
