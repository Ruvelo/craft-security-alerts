<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\console\controllers;

use craft\console\Controller;
use ruvelo\securityalerts\Plugin;
use ruvelo\securityalerts\services\CheckRunner;
use yii\console\ExitCode;

/**
 * Checks this site for known vulnerabilities in Craft and installed plugins.
 */
class CheckController extends Controller
{
    /** @var bool Print the findings as JSON */
    public bool $json = false;

    /** @var string|null Exit with code 1 when there are findings: "exploited" or "any" */
    public ?string $failOn = null;

    /** @var bool Only report: do not update stored findings or send email */
    public bool $dryRun = false;

    public function options($actionID): array
    {
        return array_merge(parent::options($actionID), ['json', 'failOn', 'dryRun']);
    }

    /**
     * Exit codes: 0 fine, 1 a finding matched --fail-on, 2 a source could not be reached or an option is wrong.
     */
    public function actionIndex(): int
    {
        $plugin = Plugin::getInstance();
        if ($plugin === null) {
            $this->stderr("The Security Alerts plugin is not installed.\n");

            return CheckRunner::EXIT_ERROR;
        }

        $code = $plugin->getCheckRunner()->run(
            $this->json,
            $this->failOn,
            $this->dryRun,
            fn(string $line) => $this->stdout($line . "\n"),
            fn(string $line) => $this->stderr('Error: ' . $line . "\n"),
        );

        return $code === 0 ? ExitCode::OK : $code;
    }
}
