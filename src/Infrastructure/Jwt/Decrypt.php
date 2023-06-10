<?php

declare(strict_types=1);

namespace Abuenosvinos\Infrastructure\Jwt;

use Abuenosvinos\Domain\Adapter\Jwt\JwtDecryptException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;

final class Decrypt
{
    private string $jwtKey;

    public function __construct(string $jwtKey)
    {
        $this->jwtKey = $jwtKey;
    }

    public function decrypt($token): array
    {
        $keyEncryptionAlgorithmManager = new AlgorithmManager([new Dir()]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([new A256GCM()]);
        $compressionMethodManager = new CompressionMethodManager([new Deflate()]);

        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $serializerManager = new JWESerializerManager([new CompactSerializer()]);
        $jwe = $serializerManager->unserialize($token);

        $key = base64_encode($this->jwtKey);
        $jwk = new JWK(['kty' => 'oct', 'k' => $key]);
        $success = $jweDecrypter->decryptUsingKey($jwe, $jwk, 0);
        if ($success) {
            return json_decode($jwe->getPayload(), true);
        }

        throw new JwtDecryptException();
    }
}
