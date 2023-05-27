<?php

declare(strict_types=1);

namespace Abuenosvinos\Infrasctructure\Jwt;

use Abuenosvinos\Domain\Adapter\Jwt\JwtAdapter as JwtDomainAdapter;

class JwtAdapter implements JwtDomainAdapter
{
    private Encrypt $encryptor;
    private Decrypt $decryptor;

    public function __construct(Encrypt $encryptor, Decrypt $decryptor)
    {
        $this->encryptor = $encryptor;
        $this->decryptor = $decryptor;
    }

    public function encrypt(array $payload): string
    {
        return $this->encryptor->encrypt(json_encode($payload));
    }

    public function decrypt(string $token): array
    {
        return $this->decryptor->decrypt($token);
    }
}
