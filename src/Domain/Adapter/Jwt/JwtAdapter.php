<?php

declare(strict_types=1);

namespace Abuenosvinos\Domain\Adapter\Jwt;

interface JwtAdapter
{
    public function encrypt(array $payload): string;

    public function decrypt(string $token): array;
}
