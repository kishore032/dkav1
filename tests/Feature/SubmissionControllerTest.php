<?php

namespace Tests\Feature;

use App\Models\PublicKey;
use App\Services\CryptoService;
use App\Services\TokenService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Redis;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * SubmissionController test suite.
 *
 * Covers POST /api/v1/challenge and POST /api/v1/submit.
 *
 * Key pairs for all six algorithms are generated once per class in
 * setUpBeforeClass() — RSA generation is slow and should not be repeated.
 */
class SubmissionControllerTest extends TestCase
{
    use RefreshDatabase;

    // Pre-generated key pairs keyed by algorithm name.
    // Shape: ['ed25519' => ['secret' => pem, 'public' => pem, 'b64' => string], ...]
    protected static array $keys = [];

    protected string $email = 'alice@example.com';
    protected TokenService $tokens;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $crypto = new CryptoService();
        foreach (['ed25519', 'secp256r1', 'secp384r1', 'rsa2048', 'rsa3072', 'rsa4096'] as $algo) {
            $pair = $crypto->generateKeys($algo);
            static::$keys[$algo] = [
                'secret' => $pair->secret_key,
                'public' => $pair->public_key,
                'b64'    => base64_encode($pair->public_key),
            ];
        }
    }

    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();

        config([
            'dka.username'      => 'dka',
            'dka.terse'         => 'no-reply',
            'dka.domain'        => 'dka.example.com',
            'dka.target_domain' => '*',
            'dka.token_ttl'     => 900,
            'dka.unlock_delay'  => 60,
        ]);

        $this->tokens = app(TokenService::class);
    }

    protected function tearDown(): void
    {
        Redis::connection('dka')->flushdb();
        parent::tearDown();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Sign $data with a private key and return a base64-encoded signature.
     *
     * Mirrors the pre-hashing strategy of CryptoService::verifyRaw() so that
     * signatures produced here will pass verification in the application code.
     */
    protected function sign(string $data, string $secretKeyPem): string
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

    /**
     * Store a key directly in the database.
     */
    protected function storeKey(
        string $emailId,
        string $selector,
        string $publicKeyPem,
        string $algorithm = 'ed25519'
    ): PublicKey {
        return PublicKey::create([
            'email_id'   => $emailId,
            'selector'   => $selector,
            'algorithm'  => $algorithm,
            'public_key' => $publicKeyPem,
            'metadata'   => '{}',
        ]);
    }

    /**
     * Store the api-selector key for $emailId and return the secret key PEM.
     */
    protected function seedApiKey(string $emailId, string $algo = 'ed25519'): string
    {
        $this->storeKey($emailId, 'api', static::$keys[$algo]['public'], $algo);
        return static::$keys[$algo]['secret'];
    }

    /**
     * Perform a full POST /api/v1/challenge round-trip and return the token.
     * The api-selector key must already be stored before calling this.
     */
    protected function freshToken(string $emailId, string $apiSecret): string
    {
        $timestamp = time();
        $apiSig    = $this->sign($emailId . '|' . $timestamp, $apiSecret);

        return $this->postJson('/api/v1/challenge', [
            'email_id'       => $emailId,
            'api_signature'  => $apiSig,
            'unix_timestamp' => $timestamp,
        ])->assertStatus(200)->json('token');
    }

    // =========================================================================
    // POST /api/v1/challenge — validation
    // =========================================================================

    #[Test]
    public function challenge_returns_422_when_email_id_is_missing(): void
    {
        $this->postJson('/api/v1/challenge', [
            'api_signature'  => 'sig',
            'unix_timestamp' => time(),
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'email_id is required']);
    }

    #[Test]
    public function challenge_returns_422_when_api_signature_is_missing(): void
    {
        $this->postJson('/api/v1/challenge', [
            'email_id'       => $this->email,
            'unix_timestamp' => time(),
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'api_signature is required']);
    }

    #[Test]
    public function challenge_returns_422_when_unix_timestamp_is_missing(): void
    {
        $this->postJson('/api/v1/challenge', [
            'email_id'      => $this->email,
            'api_signature' => 'sig',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'unix_timestamp is required']);
    }

    #[Test]
    public function challenge_returns_403_for_email_outside_target_domain(): void
    {
        config(['dka.target_domain' => 'allowed.com']);

        $this->postJson('/api/v1/challenge', [
            'email_id'       => 'alice@other.com',
            'api_signature'  => 'sig',
            'unix_timestamp' => time(),
        ])->assertStatus(403)
          ->assertJsonFragment(['error' => 'This DKA does not serve that domain']);
    }

    #[Test]
    public function challenge_returns_403_when_no_api_selector_registered(): void
    {
        $this->postJson('/api/v1/challenge', [
            'email_id'       => $this->email,
            'api_signature'  => 'sig',
            'unix_timestamp' => time(),
        ])->assertStatus(403)
          ->assertJsonFragment(['error' => 'No api selector registered for this email.']);
    }

    #[Test]
    public function challenge_returns_422_when_timestamp_is_too_old(): void
    {
        $this->seedApiKey($this->email);

        $this->postJson('/api/v1/challenge', [
            'email_id'       => $this->email,
            'api_signature'  => 'sig',
            'unix_timestamp' => time() - 400, // more than 5 minutes old
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'Timestamp out of acceptable range (±5 minutes).']);
    }

    #[Test]
    public function challenge_returns_401_when_api_signature_is_invalid(): void
    {
        $this->seedApiKey($this->email);

        $this->postJson('/api/v1/challenge', [
            'email_id'       => $this->email,
            'api_signature'  => base64_encode('badsignature'),
            'unix_timestamp' => time(),
        ])->assertStatus(401)
          ->assertJsonFragment(['error' => 'API signature verification failed.']);
    }

    #[Test]
    public function challenge_returns_409_when_token_already_exists(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        // First request issues a token
        $this->freshToken($this->email, $apiSecret);

        // Second request for the same email should be rejected
        $timestamp = time();
        $apiSig    = $this->sign($this->email . '|' . $timestamp, $apiSecret);

        $this->postJson('/api/v1/challenge', [
            'email_id'       => $this->email,
            'api_signature'  => $apiSig,
            'unix_timestamp' => $timestamp,
        ])->assertStatus(409)
          ->assertJsonFragment(['error' => 'A pending token already exists for this email.']);
    }

    #[Test]
    public function challenge_returns_200_with_token_and_expiry(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $timestamp = time();
        $apiSig    = $this->sign($this->email . '|' . $timestamp, $apiSecret);

        $response = $this->postJson('/api/v1/challenge', [
            'email_id'       => $this->email,
            'api_signature'  => $apiSig,
            'unix_timestamp' => $timestamp,
        ]);

        $response->assertStatus(200);
        $this->assertNotEmpty($response->json('token'));
        $this->assertEquals(900, $response->json('expires_in'));

        // Token is stored in Redis under the api channel
        $stored = $this->tokens->get($this->email);
        $this->assertNotNull($stored);
        $this->assertEquals('api', $stored['channel']);
        $this->assertEquals($response->json('token'), $stored['token']);
    }

    // =========================================================================
    // POST /api/v1/submit — top-level validation
    // =========================================================================

    #[Test]
    public function submit_returns_422_when_email_id_is_missing(): void
    {
        $this->postJson('/api/v1/submit', [
            'command' => 'register',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'email_id is required']);
    }

    #[Test]
    public function submit_returns_403_for_email_outside_target_domain(): void
    {
        config(['dka.target_domain' => 'allowed.com']);

        $this->postJson('/api/v1/submit', [
            'email_id' => 'alice@other.com',
            'command'  => 'register',
        ])->assertStatus(403)
          ->assertJsonFragment(['error' => 'This DKA does not serve that domain']);
    }

    #[Test]
    public function submit_returns_422_when_command_is_invalid(): void
    {
        $this->postJson('/api/v1/submit', [
            'email_id' => $this->email,
            'command'  => 'badcommand',
        ])->assertStatus(422);
    }

    #[Test]
    public function submit_returns_403_when_no_api_selector_registered(): void
    {
        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => 'any',
            'api_signature' => 'any',
        ])->assertStatus(403)
          ->assertJsonFragment(['error' => 'No api selector registered for this email.']);
    }

    #[Test]
    public function submit_returns_401_when_api_signature_is_invalid(): void
    {
        $this->seedApiKey($this->email);
        $token = $this->tokens->create($this->email, 'api');

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => base64_encode('badsig'),
        ])->assertStatus(401)
          ->assertJsonFragment(['error' => 'API signature verification failed.']);
    }

    #[Test]
    public function submit_rejects_email_channel_token(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $token     = $this->tokens->create($this->email, 'email'); // email channel, not api
        $apiSig    = $this->sign($this->email . '|' . $token, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => 'any',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => "Token was issued for the 'email' channel, not 'api'."]);
    }

    // =========================================================================
    // POST /api/v1/submit — register (error paths)
    // =========================================================================

    #[Test]
    public function submit_register_fails_when_no_active_token(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $fakeToken = str_repeat('a', 40); // not in Redis
        $apiSig    = $this->sign($this->email . '|' . $fakeToken, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $fakeToken,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => 'any',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'No active token found. Send a new email to request a challenge.']);
    }

    #[Test]
    public function submit_register_fails_when_account_is_locked(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        PublicKey::create([
            'email_id'   => $this->email,
            'selector'   => 'dka-status',
            'algorithm'  => null,
            'public_key' => null,
            'metadata'   => json_encode(['status' => 'locked']),
        ]);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        $keySig = $this->sign($this->email . '|' . $token, static::$keys['ed25519']['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => $keySig,
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'Account is locked. Send dka-status=open to unlock.']);

        $this->assertNull(PublicKey::findKey($this->email, 'default'));
    }

    #[Test]
    public function submit_register_fails_when_selector_already_exists(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $this->storeKey($this->email, 'default', static::$keys['ed25519']['public'], 'ed25519');

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        $keySig = $this->sign($this->email . '|' . $token, static::$keys['ed25519']['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => $keySig,
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => "Selector 'default' already exists. Use modify to update."]);
    }

    #[Test]
    public function submit_register_fails_for_invalid_selector_format(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'INVALID SELECTOR!', // uppercase + spaces + special chars
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => 'any',
        ])->assertStatus(422);
    }

    #[Test]
    public function submit_register_fails_for_reserved_selector(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'dka-status',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => 'any',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => "Selector 'dka-status' is reserved."]);
    }

    #[Test]
    public function submit_register_fails_for_invalid_base64_public_key(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => '!!!notbase64!!!',
            'signature'     => 'any',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'public_key is not valid base64.']);
    }

    #[Test]
    public function submit_register_fails_for_algorithm_mismatch(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'rsa2048',              // wrong: key is actually ed25519
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => 'any',
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => "Algorithm mismatch: declared 'rsa2048', detected 'ed25519'."]);
    }

    #[Test]
    public function submit_register_fails_when_key_signature_is_invalid(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$keys['ed25519']['b64'],
            'signature'     => base64_encode('invalidsig'),
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'Signature verification failed.']);

        $this->assertNull(PublicKey::findKey($this->email, 'default'));
    }

    // =========================================================================
    // POST /api/v1/submit — register (all six algorithms)
    // =========================================================================

    public static function algorithmProvider(): array
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

    #[Test]
    #[DataProvider('algorithmProvider')]
    public function submit_register_succeeds_for_algorithm(string $algo): void
    {
        // The api selector key is always ed25519; the registered key varies.
        $apiSecret = $this->seedApiKey($this->email, 'ed25519');
        $keyData   = static::$keys[$algo];
        $selector  = 'kp-' . str_replace('secp', 'p', $algo); // e.g. kp-ed25519, kp-p256r1

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        $keySig = $this->sign($this->email . '|' . $token, $keyData['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => $selector,
            'algorithm'     => $algo,
            'public_key'    => $keyData['b64'],
            'signature'     => $keySig,
        ])->assertStatus(200)
          ->assertJson(['message' => "Selector '{$selector}' registered."]);

        $stored = PublicKey::findKey($this->email, $selector);
        $this->assertNotNull($stored, "Key not stored in DB for algorithm: $algo");
        $this->assertEquals($algo, $stored->algorithm);
        $this->assertEquals($keyData['public'], $stored->public_key);
    }

    // =========================================================================
    // POST /api/v1/submit — modify
    // =========================================================================

    #[Test]
    public function submit_modify_succeeds_with_valid_old_and_new_signatures(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $this->storeKey($this->email, 'default', static::$keys['ed25519']['public'], 'ed25519');

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        // old_signature: sign with the current (ed25519) key
        $oldSig = $this->sign($this->email . '|' . $token, static::$keys['ed25519']['secret']);
        // new_signature: sign with the replacement (secp256r1) key
        $newSig = $this->sign($this->email . '|' . $token, static::$keys['secp256r1']['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'modify',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'secp256r1',
            'public_key'    => static::$keys['secp256r1']['b64'],
            'old_signature' => $oldSig,
            'new_signature' => $newSig,
        ])->assertStatus(200)
          ->assertJson(['message' => "Selector 'default' updated."]);

        $stored = PublicKey::findKey($this->email, 'default');
        $this->assertEquals('secp256r1', $stored->algorithm);
        $this->assertEquals(static::$keys['secp256r1']['public'], $stored->public_key);
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function submit_modify_fails_when_old_signature_is_wrong(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $this->storeKey($this->email, 'default', static::$keys['ed25519']['public'], 'ed25519');

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        $newSig = $this->sign($this->email . '|' . $token, static::$keys['secp256r1']['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'modify',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'secp256r1',
            'public_key'    => static::$keys['secp256r1']['b64'],
            'old_signature' => base64_encode('wrongsig'),
            'new_signature' => $newSig,
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => 'old_signature verification failed against existing key.']);

        // Key must be unchanged
        $stored = PublicKey::findKey($this->email, 'default');
        $this->assertEquals('ed25519', $stored->algorithm);
    }

    // =========================================================================
    // POST /api/v1/submit — delete
    // =========================================================================

    #[Test]
    public function submit_delete_succeeds_with_valid_signature(): void
    {
        $apiSecret = $this->seedApiKey($this->email);
        $this->storeKey($this->email, 'default', static::$keys['ed25519']['public'], 'ed25519');

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        $sig    = $this->sign($this->email . '|' . $token, static::$keys['ed25519']['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'delete',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'signature'     => $sig,
        ])->assertStatus(200)
          ->assertJson(['message' => "Selector 'default' deleted."]);

        $this->assertNull(PublicKey::findKey($this->email, 'default'));
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function submit_delete_fails_when_selector_does_not_exist(): void
    {
        $apiSecret = $this->seedApiKey($this->email);

        $token  = $this->freshToken($this->email, $apiSecret);
        $apiSig = $this->sign($this->email . '|' . $token, $apiSecret);
        $sig    = $this->sign($this->email . '|' . $token, static::$keys['ed25519']['secret']);

        $this->postJson('/api/v1/submit', [
            'email_id'      => $this->email,
            'command'       => 'delete',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'nosuchselector',
            'signature'     => $sig,
        ])->assertStatus(422)
          ->assertJsonFragment(['error' => "Selector 'nosuchselector' does not exist."]);
    }
}
