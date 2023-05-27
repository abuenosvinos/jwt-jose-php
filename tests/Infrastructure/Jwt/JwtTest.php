<?php

declare(strict_types=1);

namespace Abuenosvinos\Tests\Shared\Infrastructure\Jwt;

use Abuenosvinos\Domain\Adapter\Jwt\JwtDecryptException;
use Abuenosvinos\Infrasctructure\Jwt\Decrypt;
use Abuenosvinos\Infrasctructure\Jwt\Encrypt;
use Abuenosvinos\Infrasctructure\Jwt\JwtAdapter;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    private const JWT_KEY = 'whatever';
    public function testEncryption(): void
    {
        $payload = [
            'key1' => 'value1',
            'key2' => 'value2',
            'key3' => [
                'subkey1' => 'value3'
            ]
        ];

        $encoder = new JwtAdapter(
            new Encrypt(self::JWT_KEY),
            new Decrypt(self::JWT_KEY)
        );

        $token = $encoder->encrypt($payload);
        $this->assertIsString($token);

        $payloadBack = $encoder->decrypt($token);
        $this->assertEquals($payloadBack, $payload);
    }

    public function testDifferentJwtKey(): void
    {
        $this->expectException(JwtDecryptException::class);

        $encoder = new JwtAdapter(
            new Encrypt(self::JWT_KEY),
            new Decrypt('AnotherKey')
        );

        $token = $encoder->encrypt([]);
        $this->assertIsString($token);

        $encoder->decrypt($token);
    }
}
