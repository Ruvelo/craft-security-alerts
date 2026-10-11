<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\events;

use ruvelo\securityalerts\models\Finding;
use ruvelo\securityalerts\models\ScanResult;
use yii\base\Event;

/**
 * Triggered by {@see \ruvelo\securityalerts\services\Checker::EVENT_FINDINGS_FOUND} after a check that found something.
 */
class FindingsEvent extends Event
{
    /** @var list<Finding> Everything that applies right now, exploited first */
    public array $findings = [];

    /** @var list<Finding> New since the last check, plus findings that just became exploited */
    public array $newFindings = [];

    public ?ScanResult $result = null;
}
