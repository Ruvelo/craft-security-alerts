<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\services;

use ruvelo\securityalerts\events\FindingsEvent;
use ruvelo\securityalerts\exceptions\SourceException;
use ruvelo\securityalerts\models\CheckOutcome;
use yii\base\Component;

/**
 * One full check: scan, store what changed, tell the people who asked to be told.
 */
class Checker extends Component
{
    /**
     * @event FindingsEvent Triggered after every check that finds something, whether or not it is news.
     */
    public const EVENT_FINDINGS_FOUND = 'findingsFound';

    public const STATE_LAST_CHECK = 'last_check';

    public function __construct(
        private readonly Scanner $scanner,
        private readonly Reconciler $reconciler,
        private readonly Notifier $notifier,
        private readonly StateInterface $state,
        array $config = [],
    ) {
        parent::__construct($config);
    }

    /**
     * @throws SourceException
     */
    public function run(): CheckOutcome
    {
        $result = $this->scanner->scan();
        $changes = $this->reconciler->reconcile($result->findings);
        $this->state->set(self::STATE_LAST_CHECK, gmdate('Y-m-d H:i:s'));

        if ($result->findings !== []) {
            $this->trigger(self::EVENT_FINDINGS_FOUND, new FindingsEvent([
                'findings' => $result->findings,
                'newFindings' => array_merge($changes->new, $changes->becameExploited),
                'result' => $result,
            ]));
        }

        return new CheckOutcome($result, $changes, $this->notifier->notifyPending());
    }
}
