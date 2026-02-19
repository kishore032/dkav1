<?php

namespace Tests\Feature;

use App\Mail\DkaMail;
use App\Models\PublicKey;
use App\Services\CryptoService;
use App\Services\DkaService;
use App\Services\TokenService;
use Carbon\Carbon;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Redis;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * DkaService test suite.
 *
 * Calls DkaService methods directly (not via HTTP) using real CryptoService
 * and TokenService. Three ed25519 key pairs are pre-generated once for the
 * class: k[0] = primary key, k[1] = alternate/replacement key,
 * k[2] = API-selector key.
 */
class DkaServiceTest extends TestCase
{
    use RefreshDatabase;

    // Three pre-generated ed25519 key pairs.
    // Each entry: ['secret' => pem, 'public' => pem, 'b64' => string]
    protected static array $k = [];

    protected DkaService   $dka;
    protected TokenService $tokens;

    protected string $email       = 'alice@example.com';
    protected string $fromAddress = 'dka@dka.example.com';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $crypto = new CryptoService();
        for ($i = 0; $i < 3; $i++) {
            $pair = $crypto->generateKeys('ed25519');
            static::$k[$i] = [
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
            'dka.username'     => 'dka',
            'dka.domain'       => 'dka.example.com',
            'dka.token_ttl'    => 900,
            'dka.unlock_delay' => 60,
        ]);

        $this->tokens = app(TokenService::class);
        $this->dka    = app(DkaService::class);
    }

    protected function tearDown(): void
    {
        Redis::connection('dka')->flushdb();
        parent::tearDown();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** Sign $data with a private key, mirroring CryptoService::verifyRaw's pre-hashing. */
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

    /** Insert a row into public_keys directly. */
    private function storeKey(
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

    /** Lock the email account by inserting a dka-status=locked row. */
    private function lockAccount(string $emailId, ?string $unlocksAt = null): void
    {
        $meta = ['status' => 'locked'];
        if ($unlocksAt !== null) {
            $meta['unlocks_at'] = $unlocksAt;
        }

        PublicKey::create([
            'email_id'   => $emailId,
            'selector'   => 'dka-status',
            'algorithm'  => null,
            'public_key' => null,
            'metadata'   => json_encode($meta),
        ]);
    }

    /**
     * Build a valid single-register payload using k[0] as the key to register.
     * $token must already be in Redis under the correct channel.
     */
    private function makeRegisterPayload(string $emailId, string $token): array
    {
        return [
            'email_id'   => $emailId,
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => static::$k[0]['b64'],
            'metadata'   => [],
            'token'      => $token,
            'signature'  => $this->sign($emailId . '|' . $token, static::$k[0]['secret']),
        ];
    }

    // =========================================================================
    // handleEmailChallenge()
    // =========================================================================

    #[Test]
    public function email_challenge_dkim_fail_verbose_sends_error_email_and_no_token(): void
    {
        $this->dka->handleEmailChallenge($this->email, 'Fail', true, $this->fromAddress);

        $this->assertFalse($this->tokens->exists($this->email));
        Mail::assertSent(DkaMail::class, function (DkaMail $mail) {
            return $mail->emailSubject === 'DKA: DKIM Verification Failed';
        });
    }

    #[Test]
    public function email_challenge_dkim_fail_terse_sends_nothing_and_no_token(): void
    {
        $this->dka->handleEmailChallenge($this->email, 'Fail', false, $this->fromAddress);

        $this->assertFalse($this->tokens->exists($this->email));
        Mail::assertNothingSent();
    }

    #[Test]
    public function email_challenge_dkim_pass_creates_email_channel_token_and_sends_email(): void
    {
        $this->dka->handleEmailChallenge($this->email, 'Pass', true, $this->fromAddress);

        $this->assertTrue($this->tokens->exists($this->email));

        $stored = $this->tokens->get($this->email);
        $this->assertEquals('email', $stored['channel']);

        // Token email must contain the token value
        Mail::assertSent(DkaMail::class, function (DkaMail $mail) use ($stored) {
            return $mail->emailSubject === 'DKA: Your Verification Token'
                && str_contains($mail->messageBody, $stored['token']);
        });
    }

    #[Test]
    public function email_challenge_sends_token_email_regardless_of_verbose_flag(): void
    {
        // verbose only gates the DKIM-fail error email; the token distribution email
        // is always sent so the user can receive their token whichever address they used
        $this->dka->handleEmailChallenge($this->email, 'Pass', false, $this->fromAddress);

        $this->assertTrue($this->tokens->exists($this->email));
        Mail::assertSent(DkaMail::class, function (DkaMail $mail) {
            return $mail->emailSubject === 'DKA: Your Verification Token';
        });
    }

    #[Test]
    public function email_challenge_silently_ignores_when_token_already_exists(): void
    {
        $existing = $this->tokens->create($this->email, 'email');

        $this->dka->handleEmailChallenge($this->email, 'Pass', true, $this->fromAddress);

        // Token must be unchanged
        $this->assertEquals($existing, $this->tokens->get($this->email)['token']);
        Mail::assertNothingSent();
    }

    #[Test]
    public function email_challenge_dkim_check_is_case_insensitive(): void
    {
        foreach (['pass', 'PASS', 'Pass'] as $result) {
            Redis::connection('dka')->flushdb();

            $this->dka->handleEmailChallenge($this->email, $result, false, $this->fromAddress);
            $this->assertTrue($this->tokens->exists($this->email),
                "DKIM result '$result' should have issued a token");
        }
    }

    // =========================================================================
    // handleEmailSubmission()
    // =========================================================================

    #[Test]
    public function email_submission_null_payload_verbose_sends_error_email(): void
    {
        $this->dka->handleEmailSubmission(
            $this->email, 'register', null, true, $this->fromAddress
        );

        Mail::assertSent(DkaMail::class, function (DkaMail $mail) {
            return $mail->emailSubject === 'DKA: Missing or Invalid Attachment';
        });
    }

    #[Test]
    public function email_submission_null_payload_terse_sends_nothing(): void
    {
        $this->dka->handleEmailSubmission(
            $this->email, 'register', null, false, $this->fromAddress
        );

        Mail::assertNothingSent();
    }

    #[Test]
    public function email_submission_routes_register_and_stores_key(): void
    {
        $token   = $this->tokens->create($this->email, 'email');
        $payload = $this->makeRegisterPayload($this->email, $token);

        $this->dka->handleEmailSubmission(
            $this->email, 'register', $payload, false, $this->fromAddress
        );

        $this->assertNotNull(PublicKey::findKey($this->email, 'default'));
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function email_submission_routes_modify_and_updates_key(): void
    {
        $this->storeKey($this->email, 'default', static::$k[0]['public']);
        $token   = $this->tokens->create($this->email, 'email');
        $sigData = $this->email . '|' . $token;

        $payload = [
            'email_id'      => $this->email,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$k[1]['b64'],
            'token'         => $token,
            'old_signature' => $this->sign($sigData, static::$k[0]['secret']),
            'new_signature' => $this->sign($sigData, static::$k[1]['secret']),
        ];

        $this->dka->handleEmailSubmission(
            $this->email, 'modify', $payload, false, $this->fromAddress
        );

        $stored = PublicKey::findKey($this->email, 'default');
        $this->assertEquals(static::$k[1]['public'], $stored->public_key);
    }

    #[Test]
    public function email_submission_routes_delete_and_removes_key(): void
    {
        $this->storeKey($this->email, 'default', static::$k[0]['public']);
        $token   = $this->tokens->create($this->email, 'email');
        $payload = [
            'email_id'  => $this->email,
            'selector'  => 'default',
            'token'     => $token,
            'signature' => $this->sign($this->email . '|' . $token, static::$k[0]['secret']),
        ];

        $this->dka->handleEmailSubmission(
            $this->email, 'delete', $payload, false, $this->fromAddress
        );

        $this->assertNull(PublicKey::findKey($this->email, 'default'));
    }

    #[Test]
    public function email_submission_routes_lock_and_creates_locked_status(): void
    {
        $token   = $this->tokens->create($this->email, 'email');
        $payload = ['email_id' => $this->email, 'token' => $token];

        $this->dka->handleEmailSubmission(
            $this->email, 'dka-status=locked', $payload, false, $this->fromAddress
        );

        $status = PublicKey::findKey($this->email, 'dka-status');
        $this->assertNotNull($status);
        $this->assertEquals('locked', $status->getMetaArray()['status']);
    }

    #[Test]
    public function email_submission_routes_unlock_and_schedules_unlock(): void
    {
        $this->lockAccount($this->email);
        $token   = $this->tokens->create($this->email, 'email');
        $payload = ['email_id' => $this->email, 'token' => $token];

        $this->dka->handleEmailSubmission(
            $this->email, 'dka-status=open', $payload, false, $this->fromAddress
        );

        $status = PublicKey::findKey($this->email, 'dka-status');
        $meta   = $status->getMetaArray();
        $this->assertEquals('locked', $meta['status']);
        $this->assertArrayHasKey('unlocks_at', $meta);
        $this->assertTrue(Carbon::parse($meta['unlocks_at'])->isFuture());
    }

    #[Test]
    public function email_submission_verbose_sends_success_result_email(): void
    {
        $token   = $this->tokens->create($this->email, 'email');
        $payload = $this->makeRegisterPayload($this->email, $token);

        $this->dka->handleEmailSubmission(
            $this->email, 'register', $payload, true, $this->fromAddress
        );

        Mail::assertSent(DkaMail::class, function (DkaMail $mail) {
            return $mail->emailSubject === 'DKA: Register Successful';
        });
    }

    #[Test]
    public function email_submission_verbose_sends_failure_result_email_for_unknown_subject(): void
    {
        $this->dka->handleEmailSubmission(
            $this->email, 'unknown-command', ['token' => 'x'], true, $this->fromAddress
        );

        Mail::assertSent(DkaMail::class, function (DkaMail $mail) {
            return str_contains($mail->emailSubject, 'Failed');
        });
    }

    #[Test]
    public function email_submission_unknown_subject_terse_does_nothing(): void
    {
        $this->dka->handleEmailSubmission(
            $this->email, 'unknown-command', ['token' => 'x'], false, $this->fromAddress
        );

        Mail::assertNothingSent();
        $this->assertEquals(0, PublicKey::count());
    }

    // =========================================================================
    // handleApiChallenge()
    // =========================================================================

    #[Test]
    public function api_challenge_fails_when_no_api_selector_registered(): void
    {
        $result = $this->dka->handleApiChallenge($this->email, 'sig', time());

        $this->assertFalse($result['success']);
        $this->assertEquals(403, $result['code']);
        $this->assertStringContainsString('No api selector', $result['error']);
    }

    #[Test]
    public function api_challenge_fails_when_timestamp_is_out_of_range(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);

        $result = $this->dka->handleApiChallenge($this->email, 'sig', time() - 400);

        $this->assertFalse($result['success']);
        $this->assertEquals(422, $result['code']);
        $this->assertStringContainsString('Timestamp', $result['error']);
    }

    #[Test]
    public function api_challenge_fails_when_api_signature_is_invalid(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);

        $result = $this->dka->handleApiChallenge(
            $this->email,
            base64_encode('badsig'),
            time()
        );

        $this->assertFalse($result['success']);
        $this->assertEquals(401, $result['code']);
    }

    #[Test]
    public function api_challenge_fails_when_token_already_exists(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);
        $this->tokens->create($this->email, 'api');

        $timestamp = time();
        $sig       = $this->sign($this->email . '|' . $timestamp, static::$k[2]['secret']);

        $result = $this->dka->handleApiChallenge($this->email, $sig, $timestamp);

        $this->assertFalse($result['success']);
        $this->assertEquals(409, $result['code']);
    }

    #[Test]
    public function api_challenge_succeeds_and_returns_api_channel_token(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);

        $timestamp = time();
        $sig       = $this->sign($this->email . '|' . $timestamp, static::$k[2]['secret']);

        $result = $this->dka->handleApiChallenge($this->email, $sig, $timestamp);

        $this->assertTrue($result['success']);
        $this->assertNotEmpty($result['token']);
        $this->assertEquals(900, $result['expires_in']);

        $stored = $this->tokens->get($this->email);
        $this->assertEquals('api', $stored['channel']);
        $this->assertEquals($result['token'], $stored['token']);
    }

    // =========================================================================
    // handleApiSubmit()
    // =========================================================================

    #[Test]
    public function api_submit_fails_for_invalid_command(): void
    {
        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'hack',
            'token'         => 'x',
            'api_signature' => 'x',
        ]);

        $this->assertFalse($result['success']);
        $this->assertEquals(422, $result['code']);
    }

    #[Test]
    public function api_submit_fails_when_no_api_selector_registered(): void
    {
        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'register',
            'token'         => 'x',
            'api_signature' => 'x',
        ]);

        $this->assertFalse($result['success']);
        $this->assertEquals(403, $result['code']);
    }

    #[Test]
    public function api_submit_fails_when_api_signature_is_invalid(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);
        $token = $this->tokens->create($this->email, 'api');

        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => base64_encode('badsig'),
        ]);

        $this->assertFalse($result['success']);
        $this->assertEquals(401, $result['code']);
    }

    #[Test]
    public function api_submit_rejects_email_channel_token(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);
        $token  = $this->tokens->create($this->email, 'email'); // wrong channel
        $apiSig = $this->sign($this->email . '|' . $token, static::$k[2]['secret']);

        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$k[0]['b64'],
            'signature'     => 'any',
        ]);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString("'email' channel", $result['error']);
        $this->assertNull(PublicKey::findKey($this->email, 'default'));
    }

    #[Test]
    public function api_submit_register_stores_key_and_deletes_token(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);
        $token  = $this->tokens->create($this->email, 'api');
        $apiSig = $this->sign($this->email . '|' . $token, static::$k[2]['secret']);
        $keySig = $this->sign($this->email . '|' . $token, static::$k[0]['secret']);

        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'register',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$k[0]['b64'],
            'signature'     => $keySig,
        ]);

        $this->assertTrue($result['success']);
        $this->assertNotNull(PublicKey::findKey($this->email, 'default'));
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function api_submit_modify_updates_key_and_deletes_token(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);
        $this->storeKey($this->email, 'default', static::$k[0]['public']);

        $token   = $this->tokens->create($this->email, 'api');
        $apiSig  = $this->sign($this->email . '|' . $token, static::$k[2]['secret']);
        $sigData = $this->email . '|' . $token;

        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'modify',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => static::$k[1]['b64'],
            'old_signature' => $this->sign($sigData, static::$k[0]['secret']),
            'new_signature' => $this->sign($sigData, static::$k[1]['secret']),
        ]);

        $this->assertTrue($result['success']);
        $stored = PublicKey::findKey($this->email, 'default');
        $this->assertEquals(static::$k[1]['public'], $stored->public_key);
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function api_submit_delete_removes_key_and_deletes_token(): void
    {
        $this->storeKey($this->email, 'api', static::$k[2]['public']);
        $this->storeKey($this->email, 'default', static::$k[0]['public']);

        $token  = $this->tokens->create($this->email, 'api');
        $apiSig = $this->sign($this->email . '|' . $token, static::$k[2]['secret']);
        $sig    = $this->sign($this->email . '|' . $token, static::$k[0]['secret']);

        $result = $this->dka->handleApiSubmit($this->email, [
            'command'       => 'delete',
            'token'         => $token,
            'api_signature' => $apiSig,
            'selector'      => 'default',
            'signature'     => $sig,
        ]);

        $this->assertTrue($result['success']);
        $this->assertNull(PublicKey::findKey($this->email, 'default'));
        $this->assertFalse($this->tokens->exists($this->email));
    }

    // =========================================================================
    // processRegister() — single, error paths
    // =========================================================================

    #[Test]
    public function register_fails_when_no_token_in_redis(): void
    {
        $result = $this->dka->processRegister($this->email, [
            'token'      => 'nonexistent',
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => static::$k[0]['b64'],
            'signature'  => 'any',
        ], 'email');

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('No active token', $result['error']);
    }

    #[Test]
    public function register_fails_when_token_channel_does_not_match(): void
    {
        $token = $this->tokens->create($this->email, 'api'); // api channel

        $result = $this->dka->processRegister($this->email, [
            'token'      => $token,
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => static::$k[0]['b64'],
            'signature'  => 'any',
        ], 'email'); // expects email channel

        $this->assertFalse($result['success']);
        $this->assertStringContainsString("'api' channel", $result['error']);
    }

    #[Test]
    public function register_fails_when_token_value_does_not_match(): void
    {
        $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister($this->email, [
            'token'      => 'wrongvalue',
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => static::$k[0]['b64'],
            'signature'  => 'any',
        ], 'email');

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Token value does not match', $result['error']);
        $this->assertTrue($this->tokens->exists($this->email)); // token survives
    }

    #[Test]
    public function register_fails_when_account_is_locked(): void
    {
        $this->lockAccount($this->email);
        $token = $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister(
            $this->email, $this->makeRegisterPayload($this->email, $token), 'email'
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('locked', $result['error']);
        $this->assertNull(PublicKey::findKey($this->email, 'default'));
    }

    #[Test]
    public function register_fails_for_invalid_selector_format(): void
    {
        $token = $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister($this->email, [
            'token'      => $token,
            'selector'   => 'INVALID SELECTOR!',
            'algorithm'  => 'ed25519',
            'public_key' => static::$k[0]['b64'],
            'signature'  => 'any',
        ], 'email');

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Invalid selector', $result['error']);
    }

    #[Test]
    public function register_fails_for_reserved_selector(): void
    {
        $token = $this->tokens->create($this->email, 'email');

        foreach (PublicKey::HIDDEN_SELECTORS as $reserved) {
            $result = $this->dka->processRegister($this->email, [
                'token'      => $token,
                'selector'   => $reserved,
                'algorithm'  => 'ed25519',
                'public_key' => static::$k[0]['b64'],
                'signature'  => 'any',
            ], 'email');

            $this->assertFalse($result['success']);
            $this->assertStringContainsString('reserved', $result['error']);
        }
    }

    #[Test]
    public function register_fails_when_selector_already_exists(): void
    {
        $this->storeKey($this->email, 'default', static::$k[0]['public']);
        $token  = $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister(
            $this->email, $this->makeRegisterPayload($this->email, $token), 'email'
        );

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('already exists', $result['error']);
        $this->assertEquals(1, PublicKey::where('email_id', $this->email)
            ->where('selector', 'default')->count());
    }

    #[Test]
    public function register_fails_for_invalid_base64_public_key(): void
    {
        $token = $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister($this->email, [
            'token'      => $token,
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => '!!!notbase64!!!',
            'signature'  => 'any',
        ], 'email');

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('not valid base64', $result['error']);
    }

    #[Test]
    public function register_fails_for_algorithm_mismatch(): void
    {
        $token = $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister($this->email, [
            'token'      => $token,
            'selector'   => 'default',
            'algorithm'  => 'rsa2048',              // wrong: key is actually ed25519
            'public_key' => static::$k[0]['b64'],
            'signature'  => 'any',
        ], 'email');

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Algorithm mismatch', $result['error']);
    }

    #[Test]
    public function register_fails_for_invalid_signature_and_token_survives(): void
    {
        $token = $this->tokens->create($this->email, 'email');

        $result = $this->dka->processRegister($this->email, [
            'token'      => $token,
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => static::$k[0]['b64'],
            'signature'  => base64_encode('invalidsig'),
        ], 'email');

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Signature verification failed', $result['error']);
        $this->assertTrue($this->tokens->exists($this->email), 'Token must survive a failed register');
        $this->assertNull(PublicKey::findKey($this->email, 'default'));
    }

    #[Test]
    public function register_succeeds_and_stores_key_and_deletes_token(): void
    {
        $token  = $this->tokens->create($this->email, 'email');
        $result = $this->dka->processRegister(
            $this->email, $this->makeRegisterPayload($this->email, $token), 'email'
        );

        $this->assertTrue($result['success']);
        $this->assertStringContainsString("'default' registered", $result['message']);
        $this->assertNotNull(PublicKey::findKey($this->email, 'default'));
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function register_stores_metadata_when_provided(): void
    {
        $token  = $this->tokens->create($this->email, 'email');
        $payload = $this->makeRegisterPayload($this->email, $token);
        $payload['selector']  = 'signing';
        $payload['metadata']  = ['purpose' => 'signing', 'version' => 2];
        $payload['signature'] = $this->sign(
            $this->email . '|' . $token, static::$k[0]['secret']
        );

        $this->dka->processRegister($this->email, $payload, 'email');

        $stored = PublicKey::findKey($this->email, 'signing');
        $meta   = $stored->getMetaArray();
        $this->assertEquals('signing', $meta['purpose']);
        $this->assertEquals(2, $meta['version']);
    }

    // =========================================================================
    // processRegister() — batch
    // =========================================================================

    #[Test]
    public function register_batch_stores_all_valid_keys_and_deletes_token(): void
    {
        $token   = $this->tokens->create($this->email, 'email');
        $sigData = $this->email . '|' . $token;

        $batch = [
            [
                'email_id'  => $this->email, 'selector' => 'key1',
                'algorithm' => 'ed25519', 'public_key' => static::$k[0]['b64'],
                'token'     => $token,
                'signature' => $this->sign($sigData, static::$k[0]['secret']),
            ],
            [
                'email_id'  => $this->email, 'selector' => 'key2',
                'algorithm' => 'ed25519', 'public_key' => static::$k[1]['b64'],
                'token'     => $token,
                'signature' => $this->sign($sigData, static::$k[1]['secret']),
            ],
        ];

        $result = $this->dka->processRegister($this->email, $batch, 'email');

        $this->assertTrue($result['success']);
        $this->assertTrue($result['batch']);
        $this->assertNotNull(PublicKey::findKey($this->email, 'key1'));
        $this->assertNotNull(PublicKey::findKey($this->email, 'key2'));
        $this->assertFalse($this->tokens->exists($this->email));
    }

    #[Test]
    public function register_batch_deletes_token_even_when_some_entries_fail(): void
    {
        $token   = $this->tokens->create($this->email, 'email');
        $sigData = $this->email . '|' . $token;

        $batch = [
            [
                'email_id'  => $this->email, 'selector' => 'good',
                'algorithm' => 'ed25519', 'public_key' => static::$k[0]['b64'],
                'token'     => $token,
                'signature' => $this->sign($sigData, static::$k[0]['secret']),
            ],
            [
                'email_id'  => $this->email, 'selector' => 'bad',
                'algorithm' => 'ed25519', 'public_key' => static::$k[1]['b64'],
                'token'     => $token,
                'signature' => base64_encode('invalidsig'), // will fail
            ],
        ];

        $result = $this->dka->processRegister($this->email, $batch, 'email');

        $this->assertFalse($result['success']); // not all ok
        $this->assertTrue($result['batch']);
        $this->assertNotNull(PublicKey::findKey($this->email, 'good'));
        $this->assertNull(PublicKey::findKey($this->email, 'bad'));
        $this->assertFalse($this->tokens->exists($this->email), 'Token must be deleted after batch');
    }

    #[Test]
    public function register_batch_fails_cleanly_when_email_id_mismatches(): void
    {
        $token = $this->tokens->create($this->email, 'email');

        $batch = [
            [
                'email_id'  => 'other@example.com', // wrong email
                'selector'  => 'key1',
                'algorithm' => 'ed25519', 'public_key' => static::$k[0]['b64'],
                'token'     => $token,
                'signature' => 'any',
            ],
        ];

        $result = $this->dka->processRegister($this->email, $batch, 'email');

        $this->assertFalse($result['success']);
        $this->assertEquals('email_id mismatch', $result['results'][0]['error']);
    }

    // =========================================================================
    // checkLockStatus()
    // =========================================================================

    #[Test]
    public function check_lock_status_returns_true_when_no_status_row(): void
    {
        $this->assertTrue($this->dka->checkLockStatus($this->email));
    }

    #[Test]
    public function check_lock_status_returns_true_when_status_is_open(): void
    {
        PublicKey::create([
            'email_id'   => $this->email,
            'selector'   => 'dka-status',
            'algorithm'  => null,
            'public_key' => null,
            'metadata'   => json_encode(['status' => 'open']),
        ]);

        $this->assertTrue($this->dka->checkLockStatus($this->email));
    }

    #[Test]
    public function check_lock_status_returns_false_when_locked_with_no_unlock_scheduled(): void
    {
        $this->lockAccount($this->email);

        $this->assertFalse($this->dka->checkLockStatus($this->email));
    }

    #[Test]
    public function check_lock_status_returns_false_when_unlock_time_is_in_the_future(): void
    {
        $this->lockAccount($this->email, now()->addHour()->toIso8601String());

        $this->assertFalse($this->dka->checkLockStatus($this->email));
    }

    #[Test]
    public function check_lock_status_lazily_unlocks_and_returns_true_when_unlock_time_is_past(): void
    {
        $this->lockAccount($this->email, now()->subMinute()->toIso8601String());

        $result = $this->dka->checkLockStatus($this->email);

        $this->assertTrue($result);

        // Row must have been flipped to 'open'
        $status = PublicKey::findKey($this->email, 'dka-status');
        $this->assertEquals('open', $status->getMetaArray()['status']);
    }

    // =========================================================================
    // processLock / processUnlock edge cases (via handleEmailSubmission)
    // =========================================================================

    #[Test]
    public function lock_ignores_request_when_unlock_is_already_pending(): void
    {
        // A pending unlock means: locked + unlocks_at in the future
        $this->lockAccount($this->email, now()->addHour()->toIso8601String());
        $token   = $this->tokens->create($this->email, 'email');
        $payload = ['email_id' => $this->email, 'token' => $token];

        $this->dka->handleEmailSubmission(
            $this->email, 'dka-status=locked', $payload, false, $this->fromAddress
        );

        // unlocks_at must still be set (not overwritten with plain locked)
        $status = PublicKey::findKey($this->email, 'dka-status');
        $this->assertArrayHasKey('unlocks_at', $status->getMetaArray());
    }

    #[Test]
    public function unlock_creates_status_row_when_none_exists(): void
    {
        $token   = $this->tokens->create($this->email, 'email');
        $payload = ['email_id' => $this->email, 'token' => $token];

        $this->dka->handleEmailSubmission(
            $this->email, 'dka-status=open', $payload, false, $this->fromAddress
        );

        $status = PublicKey::findKey($this->email, 'dka-status');
        $this->assertNotNull($status);
        $meta = $status->getMetaArray();
        $this->assertArrayHasKey('unlocks_at', $meta);
        $this->assertTrue(Carbon::parse($meta['unlocks_at'])->isFuture());
    }
}
