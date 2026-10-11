<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use RuntimeException;
use yii\mail\BaseMailer;

class FakeMailer extends BaseMailer
{
    public $messageClass = FakeMessage::class;

    /** @var list<FakeMessage> */
    public array $sent = [];

    public bool $failing = false;

    protected function sendMessage($message): bool
    {
        if ($this->failing) {
            throw new RuntimeException('SMTP is down.');
        }
        assert($message instanceof FakeMessage);
        $this->sent[] = $message;

        return true;
    }
}
