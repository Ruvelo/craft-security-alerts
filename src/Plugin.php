<?php

declare(strict_types=1);

namespace ruvelo\securityalerts;

use Craft;
use craft\base\Model;
use craft\base\Plugin as BasePlugin;
use craft\events\RegisterComponentTypesEvent;
use craft\events\RegisterUserPermissionsEvent;
use craft\helpers\UrlHelper;
use craft\services\Dashboard;
use craft\services\UserPermissions;
use craft\services\Utilities;
use craft\web\Request as WebRequest;
use ruvelo\securityalerts\jobs\CheckJob;
use ruvelo\securityalerts\models\Settings;
use ruvelo\securityalerts\services\AdvisoryMatcher;
use ruvelo\securityalerts\services\Checker;
use ruvelo\securityalerts\services\CheckRunner;
use ruvelo\securityalerts\services\ComposerLock;
use ruvelo\securityalerts\services\DailyTrigger;
use ruvelo\securityalerts\services\FindingStore;
use ruvelo\securityalerts\services\Notifier;
use ruvelo\securityalerts\services\Reconciler;
use ruvelo\securityalerts\services\Scanner;
use ruvelo\securityalerts\services\State;
use ruvelo\securityalerts\sources\AdvisoryClient;
use ruvelo\securityalerts\sources\GuzzleFetcher;
use ruvelo\securityalerts\sources\KevCatalogue;
use ruvelo\securityalerts\utilities\SecurityAlertsUtility;
use ruvelo\securityalerts\widgets\SecurityAlertsWidget;
use Throwable;
use yii\base\Event;

/**
 * Security Alerts for Craft CMS.
 *
 * @method Settings getSettings()
 */
class Plugin extends BasePlugin
{
    public const PERMISSION_VIEW = 'securityAlerts-view';

    public string $schemaVersion = '1.0.0';

    public bool $hasCpSettings = true;

    public function init(): void
    {
        parent::init();

        Craft::setAlias('@ruvelo/securityalerts', __DIR__);

        Event::on(
            Utilities::class,
            Utilities::EVENT_REGISTER_UTILITIES,
            static function(RegisterComponentTypesEvent $event): void {
                $event->types[] = SecurityAlertsUtility::class;
            },
        );

        Event::on(
            Dashboard::class,
            Dashboard::EVENT_REGISTER_WIDGET_TYPES,
            static function(RegisterComponentTypesEvent $event): void {
                $event->types[] = SecurityAlertsWidget::class;
            },
        );

        Event::on(
            UserPermissions::class,
            UserPermissions::EVENT_REGISTER_PERMISSIONS,
            static function(RegisterUserPermissionsEvent $event): void {
                $event->permissions[] = [
                    'heading' => Craft::t('security-alerts', 'Security Alerts'),
                    'permissions' => [
                        self::PERMISSION_VIEW => [
                            'label' => Craft::t('security-alerts', 'View security alerts and run a check'),
                        ],
                    ],
                ];
            },
        );

        $request = Craft::$app->getRequest();
        if ($request instanceof WebRequest && $request->getIsCpRequest()) {
            Craft::$app->onInit(function(): void {
                $this->queueCheckIfDue();
            });
        }
    }

    /**
     * The fallback for sites without a cron job: when someone opens the control panel and no
     * check has run for a day, push one onto the queue. Never in the request's way.
     */
    private function queueCheckIfDue(): void
    {
        $request = Craft::$app->getRequest();
        if (!$request instanceof WebRequest || !$request->getIsGet() || $request->getIsAjax() || Craft::$app->getUser()->getIdentity() === null) {
            return;
        }
        $settings = $this->getSettings();
        if (!$settings->enabled || !$settings->checkOnCpUse) {
            return;
        }

        try {
            if ((new DailyTrigger(new State()))->claim(time())) {
                Craft::$app->getQueue()->push(new CheckJob());
            }
        } catch (Throwable $e) {
            // The tables may not exist yet while an update is pending. Never break the control panel.
            Craft::warning('Could not queue the daily check: ' . $e->getMessage(), 'security-alerts');
        }
    }

    public function getChecker(): Checker
    {
        $store = new FindingStore();
        $siteName = Craft::$app->getSystemName();

        return new Checker(
            $this->getScanner(),
            new Reconciler($store),
            new Notifier(
                $this->getSettings(),
                $store,
                Craft::$app->getMailer(),
                $siteName,
                UrlHelper::cpUrl('utilities/security-alerts'),
            ),
            new State(),
        );
    }

    public function getScanner(): Scanner
    {
        $fetcher = new GuzzleFetcher(Craft::createGuzzleClient());

        return new Scanner(
            new ComposerLock(Craft::getAlias('@root/composer.lock')),
            new AdvisoryClient($fetcher),
            new KevCatalogue($fetcher),
            new AdvisoryMatcher(),
            Craft::$app->getVersion(),
        );
    }

    public function getCheckRunner(): CheckRunner
    {
        return new CheckRunner($this->getScanner(), $this->getChecker());
    }

    protected function createSettingsModel(): ?Model
    {
        return new Settings();
    }

    protected function settingsHtml(): ?string
    {
        return Craft::$app->getView()->renderTemplate('security-alerts/_settings', [
            'settings' => $this->getSettings(),
        ]);
    }
}
