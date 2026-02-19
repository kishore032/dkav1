<?php

namespace App\Services;

use Exception;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey as RSAPublicKey;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;

class CryptoService
{
    /**
     * Detect the algorithm of a PKCS#8 PEM public key.
     *
     * @param  string  $pem  Raw PEM string (not base64-encoded)
     * @return string|null  One of: ed25519, secp256r1, secp384r1, rsa2048, rsa3072, rsa4096
     */
    public function detectAlgorithm(string $pem): ?string
    {
        try {
            $key = PublicKeyLoader::load($pem);
        } catch (Exception $e) {
            return null;
        }

        if (!($key instanceof PublicKey || $key instanceof PrivateKey
            || $key instanceof RSAPublicKey || $key instanceof RSAPrivateKey)) {
            return null;
        }

        if ($key->getLoadedFormat() !== 'PKCS8') {
            return null;
        }

        if ($key instanceof RSAPublicKey || $key instanceof RSAPrivateKey) {
            $length = $key->getLength();
            if (in_array($length, [2048, 3072, 4096])) {
                return 'rsa' . $length;
            }
            return null;
        }

        $curve = method_exists($key, 'getCurve') ? strtolower($key->getCurve()) : '';
        if (in_array($curve, ['ed25519', 'secp256r1', 'secp384r1'])) {
            return $curve;
        }

        return null;
    }

    /**
     * Verify a base64-encoded signature over $data using a PKCS#8 PEM public key.
     *
     * The data is pre-hashed according to the key's algorithm before verification
     * (except Ed25519, which handles hashing internally).
     *
     * @param  string  $data       Raw payload string (e.g. "user@example.com|token")
     * @param  string  $signature  Base64-encoded signature
     * @param  string  $pem        PKCS#8 PEM public key string
     * @return bool|null  true=valid, false=invalid, null=error loading key
     */
    public function verifyRaw(string $data, string $signature, string $pem): ?bool
    {
        try {
            $key = PublicKeyLoader::load($pem);
        } catch (Exception $e) {
            return null;
        }

        if (!($key instanceof PublicKey || $key instanceof RSAPublicKey)) {
            return null;
        }

        if ($key instanceof RSAPublicKey) {
            $hashAlgs = [4096 => 'sha512', 3072 => 'sha384', 2048 => 'sha256'];
            $hashAlg  = $hashAlgs[$key->getLength()] ?? null;
        } else {
            $curve    = method_exists($key, 'getCurve') ? $key->getCurve() : '';
            $hashAlgs = ['Ed25519' => null, 'secp256r1' => 'sha256', 'secp384r1' => 'sha384'];
            $hashAlg  = $hashAlgs[$curve] ?? null;
        }

        if ($hashAlg !== null) {
            $data = hash($hashAlg, $data, true);
        }

        try {
            return $key->verify($data, base64_decode($signature));
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Generate a key pair for the specified algorithm.
     * Returns an object with secret_key and public_key (both PKCS#8 PEM strings).
     * Intended for testing and reference use.
     *
     * @param  string  $algo  One of: ed25519, secp256r1, secp384r1, rsa2048, rsa3072, rsa4096
     * @return object|null  {secret_key, public_key}
     */
    public function generateKeys(string $algo): ?object
    {
        switch (strtolower($algo)) {
            case 'ed25519':
            case 'secp256r1':
            case 'secp384r1':
                $keypair = EC::createKey($algo);
                break;
            case 'rsa2048':
            case 'rsa3072':
            case 'rsa4096':
                $keypair = RSA::createKey((int) substr($algo, 3, 4));
                break;
            default:
                return null;
        }

        return (object) [
            'secret_key' => $keypair->toString('pkcs8'),
            'public_key' => $keypair->getPublicKey()->toString('pkcs8'),
        ];
    }
}
