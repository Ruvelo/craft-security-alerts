<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\sources;

use ruvelo\securityalerts\exceptions\SourceException;

interface FetcherInterface
{
    /**
     * @return string Response body
     * @throws SourceException
     */
    public function get(string $url): string;

    /**
     * @param string $formBody An application/x-www-form-urlencoded body
     * @return string Response body
     * @throws SourceException
     */
    public function postForm(string $url, string $formBody): string;
}
