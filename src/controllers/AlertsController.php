<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\controllers;

use Craft;
use craft\helpers\UrlHelper;
use craft\web\Controller;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\Findings;
use ruvelo\securityalerts\Plugin;
use yii\web\Response;

class AlertsController extends Controller
{
    protected array|bool|int $allowAnonymous = self::ALLOW_ANONYMOUS_NEVER;

    /**
     * Runs a check now, from the "Check now" button. A POST, so Craft's CSRF validation applies, for people who may view the alerts.
     */
    public function actionCheck(): ?Response
    {
        $this->requirePostRequest();
        $this->requireCpRequest();
        $this->requirePermission(Plugin::PERMISSION_VIEW);

        $plugin = Plugin::getInstance();
        if ($plugin === null) {
            return $this->asFailure(Craft::t('security-alerts', 'The plugin is not installed.'));
        }

        try {
            $outcome = $plugin->getChecker()->run();
        } catch (SourceException $e) {
            return $this->asFailure($e->getMessage());
        }

        $total = count($outcome->result->findings);
        $exploited = Findings::exploitedCount($outcome->result->findings);

        return $this->asSuccess(
            $total === 0
                ? Craft::t('security-alerts', 'No known vulnerabilities found in {n} packages.', ['n' => $outcome->result->packagesChecked])
                : Craft::t('security-alerts', '{total} findings, {exploited} exploited.', ['total' => $total, 'exploited' => $exploited]),
            [
                'total' => $total,
                'exploited' => $exploited,
                'packagesChecked' => $outcome->result->packagesChecked,
                'warnings' => $outcome->result->warnings,
            ],
            UrlHelper::cpUrl('utilities/security-alerts'),
        );
    }
}
