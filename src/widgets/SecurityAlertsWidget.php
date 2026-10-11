<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\widgets;

use Craft;
use craft\base\Widget;
use craft\helpers\UrlHelper;
use ruvelo\securityalerts\assets\AlertsAsset;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\Plugin;
use ruvelo\securityalerts\services\FindingStore;

/**
 * A dashboard widget: how many open findings, and whether any are exploited.
 */
class SecurityAlertsWidget extends Widget
{
    public static function displayName(): string
    {
        return Craft::t('security-alerts', 'Security alerts');
    }

    public static function icon(): ?string
    {
        return Craft::getAlias('@ruvelo/securityalerts/icon-mask.svg');
    }

    public static function isSelectable(): bool
    {
        return Craft::$app->getUser()->checkPermission(Plugin::PERMISSION_VIEW);
    }

    public function getTitle(): ?string
    {
        return Craft::t('security-alerts', 'Security alerts');
    }

    public function getBodyHtml(): ?string
    {
        if (!Craft::$app->getUser()->checkPermission(Plugin::PERMISSION_VIEW)) {
            return null;
        }
        $view = Craft::$app->getView();
        $view->registerAssetBundle(AlertsAsset::class);

        $findings = Findings::sorted((new FindingStore())->all());

        return $view->renderTemplate('security-alerts/_widget', [
            'total' => count($findings),
            'exploited' => Findings::exploitedCount($findings),
            'top' => array_slice($findings, 0, 3),
            'url' => Craft::$app->getUser()->checkPermission('utility:security-alerts')
                ? UrlHelper::cpUrl('utilities/security-alerts')
                : null,
        ]);
    }
}
