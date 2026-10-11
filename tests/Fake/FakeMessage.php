<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\tests\Fake;

use yii\mail\BaseMessage;

/**
 * Keeps what it is given, for assertions.
 */
class FakeMessage extends BaseMessage
{
    /** @var array<string, mixed> */
    public array $parts = [];

    public function getCharset(): string
    {
        return 'utf-8';
    }

    public function setCharset($charset): static
    {
        return $this;
    }

    /**
     * @return array<int|string, string>|string
     */
    public function getFrom(): array|string
    {
        return $this->parts['from'] ?? '';
    }

    /**
     * @param array<int|string, string>|string $from
     */
    public function setFrom($from): static
    {
        $this->parts['from'] = $from;

        return $this;
    }

    /**
     * @return array<int|string, string>|string
     */
    public function getReplyTo(): array|string
    {
        return '';
    }

    /**
     * @param array<int|string, string>|string $replyTo
     */
    public function setReplyTo($replyTo): static
    {
        return $this;
    }

    /**
     * @return array<int|string, string>|string
     */
    public function getTo(): array|string
    {
        return $this->parts['to'] ?? '';
    }

    /**
     * @param array<int|string, string>|string $to
     */
    public function setTo($to): static
    {
        $this->parts['to'] = $to;

        return $this;
    }

    /**
     * @return array<int|string, string>|string
     */
    public function getCc(): array|string
    {
        return '';
    }

    /**
     * @param array<int|string, string>|string $cc
     */
    public function setCc($cc): static
    {
        return $this;
    }

    /**
     * @return array<int|string, string>|string
     */
    public function getBcc(): array|string
    {
        return '';
    }

    /**
     * @param array<int|string, string>|string $bcc
     */
    public function setBcc($bcc): static
    {
        return $this;
    }

    public function getSubject(): string
    {
        return (string)($this->parts['subject'] ?? '');
    }

    public function setSubject($subject): static
    {
        $this->parts['subject'] = $subject;

        return $this;
    }

    public function setTextBody($text): static
    {
        $this->parts['text'] = $text;

        return $this;
    }

    public function setHtmlBody($html): static
    {
        $this->parts['html'] = $html;

        return $this;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function attach($fileName, array $options = []): static
    {
        return $this;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function attachContent($content, array $options = []): static
    {
        return $this;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function embed($fileName, array $options = []): string
    {
        return '';
    }

    /**
     * @param array<string, mixed> $options
     */
    public function embedContent($content, array $options = []): string
    {
        return '';
    }

    public function toString(): string
    {
        return implode("\n", array_map(static fn(mixed $p): string => is_scalar($p) ? (string)$p : (string)json_encode($p), $this->parts));
    }
}
