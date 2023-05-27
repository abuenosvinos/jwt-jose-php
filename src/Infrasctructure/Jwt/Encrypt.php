<?php

declare(strict_types=1);

namespace Abuenosvinos\Infrasctructure\Jwt;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;

final class Encrypt
{
    private string $jwtKey;

    public function __construct(string $jwtKey)
    {
        $this->jwtKey = $jwtKey;
    }

    public function encrypt(string $payload): string
    {
        $key = base64_encode($this->jwtKey);
        $jwk = new JWK(['kty' => 'oct', 'k' => $key]);

        $keyEncryptionAlgorithmManager = new AlgorithmManager([new Dir()]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([new A256GCM()]);
        $compressionMethodManager = new CompressionMethodManager([new Deflate()]);

        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $jwe = $jweBuilder
            ->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader([
                'alg' => 'dir',
                'enc' => 'A256GCM',
                'zip' => 'DEF'
            ])
            ->addRecipient($jwk)
            ->build();

        $serializer = new CompactSerializer();

        return $serializer->serialize($jwe, 0);
    }
}
