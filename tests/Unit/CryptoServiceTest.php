<?php

namespace Tests\Unit;

use App\Services\CryptoService;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CryptoService unit tests.
 *
 * Exercises generateKeys(), detectAlgorithm(), and verifyRaw() across
 * all six supported algorithms. Two independent key sets (primary and
 * alternate) are generated once for the class in setUpBeforeClass() so
 * that slow RSA generation is never repeated per-test.
 */
class CryptoServiceTest extends TestCase
{
    protected static array $keys    = []; // primary set
    protected static array $altKeys = []; // alternate set — used for "wrong key" tests

    protected CryptoService $crypto;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $crypto = new CryptoService();
        $algos  = ['ed25519', 'secp256r1', 'secp384r1', 'rsa2048', 'rsa3072', 'rsa4096'];

        foreach ($algos as $algo) {
            $a = $crypto->generateKeys($algo);
            $b = $crypto->generateKeys($algo);

            static::$keys[$algo]    = ['secret' => $a->secret_key, 'public' => $a->public_key];
            static::$altKeys[$algo] = ['secret' => $b->secret_key, 'public' => $b->public_key];
        }
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->crypto = new CryptoService();
    }

    // -------------------------------------------------------------------------
    // Internal signing helper — mirrors CryptoService::verifyRaw pre-hashing.
    // -------------------------------------------------------------------------

    private function sign(string $data, string $secretKeyPem): string
    {
        $key = PublicKeyLoader::load($secretKeyPem);

        if ($key instanceof RSAPrivateKey) {
            $hashAlgs = [4096 => 'sha512', 3072 => 'sha384', 2048 => 'sha256'];
            $hashAlg  = $hashAlgs[$key->getLength()] ?? 'sha256';
            $payload  = hash($hashAlg, $data, true);
        } else {
            $curve    = method_exists($key, 'getCurve') ? $key->getCurve() : null;
            $hashAlgs = ['Ed25519' => null, 'secp256r1' => 'sha256', 'secp384r1' => 'sha384'];
            $hashAlg  = $hashAlgs[$curve] ?? null;
            $payload  = $hashAlg ? hash($hashAlg, $data, true) : $data;
        }

        return base64_encode($key->sign($payload));
    }

    // =========================================================================
    // Data providers
    // =========================================================================

    public static function allAlgorithms(): array
    {
        return [
            'ed25519'   => ['ed25519'],
            'secp256r1' => ['secp256r1'],
            'secp384r1' => ['secp384r1'],
            'rsa2048'   => ['rsa2048'],
            'rsa3072'   => ['rsa3072'],
            'rsa4096'   => ['rsa4096'],
        ];
    }

    public static function ecAlgorithms(): array
    {
        return [
            'ed25519'   => ['ed25519',   'ed25519'],
            'secp256r1' => ['secp256r1', 'secp256r1'],
            'secp384r1' => ['secp384r1', 'secp384r1'],
        ];
    }

    public static function rsaAlgorithms(): array
    {
        return [
            'rsa2048' => ['rsa2048', 2048],
            'rsa3072' => ['rsa3072', 3072],
            'rsa4096' => ['rsa4096', 4096],
        ];
    }

    // =========================================================================
    // generateKeys()
    // =========================================================================

    #[Test]
    public function generate_keys_returns_null_for_unknown_algorithm(): void
    {
        $this->assertNull($this->crypto->generateKeys('dh2048'));
        $this->assertNull($this->crypto->generateKeys('rsa1024'));
        $this->assertNull($this->crypto->generateKeys(''));
    }

    #[Test]
    public function generate_keys_is_case_insensitive(): void
    {
        $pair = $this->crypto->generateKeys('ED25519');
        $this->assertNotNull($pair);
        $this->assertObjectHasProperty('secret_key', $pair);
        $this->assertObjectHasProperty('public_key', $pair);
    }

    #[Test]
    public function generate_keys_returns_object_with_correct_property_names(): void
    {
        $pair = $this->crypto->generateKeys('secp256r1');
        $this->assertObjectHasProperty('secret_key', $pair);
        $this->assertObjectHasProperty('public_key', $pair);
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function generate_keys_output_has_correct_structure(string $algo): void
    {
        $pair = static::$keys[$algo];

        // Both are non-empty PEM strings
        $this->assertNotEmpty($pair['secret']);
        $this->assertNotEmpty($pair['public']);
        $this->assertStringStartsWith('-----BEGIN', $pair['secret']);
        $this->assertStringStartsWith('-----BEGIN', $pair['public']);

        // Secret and public keys are distinct
        $this->assertNotEquals($pair['secret'], $pair['public']);

        // Both load as PKCS#8 format
        $this->assertEquals('PKCS8', PublicKeyLoader::load($pair['public'])->getLoadedFormat(),
            "Public key for $algo is not PKCS8");
        $this->assertEquals('PKCS8', PublicKeyLoader::load($pair['secret'])->getLoadedFormat(),
            "Secret key for $algo is not PKCS8");
    }

    #[Test]
    #[DataProvider('rsaAlgorithms')]
    public function generate_keys_rsa_has_correct_bit_length(string $algo, int $expectedBits): void
    {
        $pub = PublicKeyLoader::load(static::$keys[$algo]['public']);
        $this->assertEquals($expectedBits, $pub->getLength());
    }

    #[Test]
    #[DataProvider('ecAlgorithms')]
    public function generate_keys_ec_has_correct_curve(string $algo, string $expectedCurve): void
    {
        $pub   = PublicKeyLoader::load(static::$keys[$algo]['public']);
        $curve = method_exists($pub, 'getCurve') ? strtolower($pub->getCurve()) : '';
        $this->assertEquals($expectedCurve, $curve);
    }

    #[Test]
    public function generate_keys_produces_independent_pairs_each_call(): void
    {
        // Two calls must not return the same keys (astronomically unlikely to collide)
        $this->assertNotEquals(
            static::$keys['ed25519']['secret'],
            static::$altKeys['ed25519']['secret']
        );
        $this->assertNotEquals(
            static::$keys['rsa2048']['public'],
            static::$altKeys['rsa2048']['public']
        );
    }

    // =========================================================================
    // detectAlgorithm()
    // =========================================================================

    #[Test]
    public function detect_algorithm_returns_null_for_garbage_input(): void
    {
        $this->assertNull($this->crypto->detectAlgorithm('not a key'));
        $this->assertNull($this->crypto->detectAlgorithm(''));
        // Valid-looking PEM header but garbage body
        $garbage = "-----BEGIN PUBLIC KEY-----\n" . base64_encode('garbage data') . "\n-----END PUBLIC KEY-----";
        $this->assertNull($this->crypto->detectAlgorithm($garbage));
    }

    #[Test]
    public function detect_algorithm_returns_null_for_non_pkcs8_format(): void
    {
        // Export an RSA public key in PKCS#1 format (not PKCS#8)
        $pub      = PublicKeyLoader::load(static::$keys['rsa2048']['public']);
        $pkcs1Pem = $pub->toString('PKCS1');

        $this->assertNull($this->crypto->detectAlgorithm($pkcs1Pem));
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function detect_algorithm_identifies_public_key_algorithm(string $algo): void
    {
        $result = $this->crypto->detectAlgorithm(static::$keys[$algo]['public']);
        $this->assertEquals($algo, $result,
            "detectAlgorithm returned '$result' for $algo public key");
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function detect_algorithm_identifies_private_key_algorithm(string $algo): void
    {
        $result = $this->crypto->detectAlgorithm(static::$keys[$algo]['secret']);
        $this->assertEquals($algo, $result,
            "detectAlgorithm returned '$result' for $algo private key");
    }

    // =========================================================================
    // verifyRaw()
    // =========================================================================

    #[Test]
    public function verify_raw_returns_null_for_invalid_pem(): void
    {
        $this->assertNull($this->crypto->verifyRaw('data', base64_encode('sig'), 'not a key'));
        $this->assertNull($this->crypto->verifyRaw('data', base64_encode('sig'), ''));
    }

    #[Test]
    public function verify_raw_returns_null_for_private_key_pem(): void
    {
        // verifyRaw only accepts public keys; passing a private key must return null
        $result = $this->crypto->verifyRaw(
            'data',
            base64_encode('sig'),
            static::$keys['ed25519']['secret']
        );
        $this->assertNull($result);
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function verify_raw_returns_true_for_valid_signature(string $algo): void
    {
        $payload = 'alice@example.com|verifytest';
        $sig     = $this->sign($payload, static::$keys[$algo]['secret']);

        $result = $this->crypto->verifyRaw($payload, $sig, static::$keys[$algo]['public']);
        $this->assertTrue($result, "Valid signature rejected for $algo");
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function verify_raw_returns_false_for_tampered_data(string $algo): void
    {
        $original = 'alice@example.com|verifytest';
        $tampered = 'alice@example.com|TAMPERED!!!';
        $sig      = $this->sign($original, static::$keys[$algo]['secret']);

        $result = $this->crypto->verifyRaw($tampered, $sig, static::$keys[$algo]['public']);
        $this->assertFalse($result, "Tampered data should not verify for $algo");
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function verify_raw_returns_false_for_signature_from_different_key(string $algo): void
    {
        // Sign with primary key, verify against alternate key of the same algorithm
        $payload = 'alice@example.com|verifytest';
        $sig     = $this->sign($payload, static::$keys[$algo]['secret']);

        $result = $this->crypto->verifyRaw($payload, $sig, static::$altKeys[$algo]['public']);
        $this->assertFalse($result, "Signature verified against wrong $algo key");
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function verify_raw_returns_not_true_for_corrupted_signature(string $algo): void
    {
        $payload = 'alice@example.com|verifytest';

        // Well-formed base64 but random bytes — invalid signature content
        $garbage = base64_encode(random_bytes(64));
        $result  = $this->crypto->verifyRaw($payload, $garbage, static::$keys[$algo]['public']);
        $this->assertNotSame(true, $result, "Random-byte signature should not verify for $algo");
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function verify_raw_is_consistent_across_multiple_calls(string $algo): void
    {
        // The same payload+signature+key must always verify the same way
        $payload = 'consistency@example.com|token999';
        $sig     = $this->sign($payload, static::$keys[$algo]['secret']);

        $first  = $this->crypto->verifyRaw($payload, $sig, static::$keys[$algo]['public']);
        $second = $this->crypto->verifyRaw($payload, $sig, static::$keys[$algo]['public']);

        $this->assertTrue($first,  "First verification failed for $algo");
        $this->assertTrue($second, "Second verification failed for $algo");
    }
}
