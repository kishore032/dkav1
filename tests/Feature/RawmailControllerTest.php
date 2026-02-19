<?php

namespace Tests\Feature;

use App\Http\Controllers\RawmailController;
use App\Mail\DkaMail;
use App\Models\PublicKey;
use App\Models\Rawmail;
use App\Services\CryptoService;
use App\Services\DkaService;
use App\Services\TokenService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Redis;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * RawmailController test suite.
 *
 * Every test calls $this->controller->receive($post, $files, true) directly,
 * bypassing $_POST/$_FILES and move_uploaded_file() entirely.
 *
 * $files shape: ['attachment-1' => ['tmp_name' => '/tmp/file', 'name' => 'x.json', 'error' => 0, 'size' => N]]
 */
class RawmailControllerTest extends TestCase
{
    use RefreshDatabase;

    protected RawmailController $controller;
    protected CryptoService     $crypto;
    protected TokenService      $tokens;

    // A valid Mailgun webhook signature is generated from these
    protected string $mgSigningKey = 'test-signing-key';
    protected string $timestamp    = '1739884800';
    protected string $mgToken      = 'testtoken123';
    protected string $signature;

    // Default sender/recipient used in most tests
    protected string $senderEmail    = 'alice@example.com';
    protected string $recipientEmail = 'dka@dka.example.com';

    protected function tearDown(): void
    {
        // Remove any files written to storage/app/rawmails/ during this test
        $base = storage_path('app/rawmails');
        if (is_dir($base)) {
            foreach (glob($base . '/*', GLOB_ONLYDIR) as $dir) {
                foreach (glob($dir . '/*') as $file) {
                    @unlink($file);
                }
                @rmdir($dir);
            }
        }

        Redis::connection('dka')->flushdb();
        parent::tearDown();
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Fake outbound email so no real SMTP calls happen
        Mail::fake();

        // Set DKA config to match test fixtures
        config([
            'dka.username'      => 'dka',
            'dka.terse'         => 'no-reply',
            'dka.domain'        => 'dka.example.com',
            'dka.target_domain' => '*',
            'dka.token_ttl'     => 900,
            'dka.unlock_delay'  => 60,
            'dka.mg_signing_key' => $this->mgSigningKey,
        ]);

        // Pre-compute a valid Mailgun signature for use in $post
        $this->signature = hash_hmac('sha256', $this->timestamp . $this->mgToken, $this->mgSigningKey);

        $this->crypto     = new CryptoService();
        $this->tokens     = app(TokenService::class);
        $this->controller = new RawmailController(app(DkaService::class), $this->tokens);
    }

    // =========================================================================
    // Helper factories
    // =========================================================================

    /**
     * Build a minimal valid $post array (Step 1 — challenge request).
     */
    protected function makePost(array $overrides = []): array
    {
        return array_merge([
            'Message-Id'                    => '<test-' . uniqid() . '@example.com>',
            'From'                          => 'Alice <' . $this->senderEmail . '>',
            'recipient'                     => $this->recipientEmail,
            'subject'                       => '',
            'timestamp'                     => $this->timestamp,
            'token'                         => $this->mgToken,
            'signature'                     => $this->signature,
            'X-Mailgun-Dkim-Check-Result'   => 'Pass',
            'X-Mailgun-Spf'                 => 'Pass',
            'X-Mailgun-Sflag'               => 'No',
            'attachment-count'              => '0',
        ], $overrides);
    }

    /**
     * Write $content to a temp file and return a $_FILES-shaped entry.
     */
    protected function makeTempAttachment(string $content, string $name = 'payload.json'): array
    {
        $tmpPath = tempnam(sys_get_temp_dir(), 'dka_test_');
        file_put_contents($tmpPath, $content);

        return [
            'attachment-1' => [
                'name'     => $name,
                'tmp_name' => $tmpPath,
                'error'    => 0,
                'size'     => strlen($content),
            ],
        ];
    }

    /**
     * Generate a fresh key pair and return [secret_key_pem, public_key_pem, public_key_b64].
     */
    protected function generateKeyPair(string $algo = 'ed25519'): array
    {
        $pair   = $this->crypto->generateKeys($algo);
        $b64Pub = base64_encode($pair->public_key);
        return [$pair->secret_key, $pair->public_key, $b64Pub];
    }

    /**
     * Sign "email_id|token" with a private key and return base64 signature.
     */
    protected function sign(string $data, string $secretKeyPem): string
    {
        // Use phpseclib directly for signing in tests
        $key = \phpseclib3\Crypt\PublicKeyLoader::load($secretKeyPem);
        $curve = method_exists($key, 'getCurve') ? $key->getCurve() : null;
        $hashAlgs = ['Ed25519' => null, 'secp256r1' => 'sha256', 'secp384r1' => 'sha384'];
        $hashAlg  = $hashAlgs[$curve] ?? null;
        $payload  = $hashAlg ? hash($hashAlg, $data, true) : $data;
        return base64_encode($key->sign($payload));
    }

    /**
     * Pre-store a key in the public_keys table.
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

    // =========================================================================
    // Basic validation tests
    // =========================================================================

    #[Test]
    public function it_returns_406_if_post_is_not_an_array(): void
    {
        $result = $this->controller->receive(null, null, true);
        $this->assertEquals(406, $result->getStatusCode());
    }

    #[Test]
    public function it_returns_406_if_message_id_is_missing(): void
    {
        $post = $this->makePost();
        unset($post['Message-Id']);

        $result = $this->controller->receive($post, [], true);
        $this->assertEquals(406, $result->getStatusCode());
    }

    #[Test]
    public function it_returns_200_for_duplicate_message_id(): void
    {
        $post = $this->makePost();
        Rawmail::create([
            'message_id'       => $post['Message-Id'],
            'from_email'       => $this->senderEmail,
            'to_email'         => $this->recipientEmail,
            'subject'          => '',
            'timestamp'        => $this->timestamp,
            'spam_flag'        => 'No',
            'dkim_check'       => 'Pass',
            'spf_check'        => 'Pass',
            'attachment_count' => 0,
        ]);

        // Second call with the same Message-Id should short-circuit
        $result = $this->controller->receive($post, [], true);
        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals(1, Rawmail::count()); // no second record created
    }

    #[Test]
    public function it_returns_401_for_invalid_mailgun_signature(): void
    {
        $post = $this->makePost(['signature' => 'invalidsignature']);

        $result = $this->controller->receive($post, [], true);
        $this->assertEquals(401, $result->getStatusCode());
    }

    #[Test]
    public function it_returns_406_for_unparseable_from_address(): void
    {
        $post = $this->makePost(['From' => 'notanemail']);

        $result = $this->controller->receive($post, [], true);
        $this->assertEquals(406, $result->getStatusCode());
    }

    #[Test]
    public function it_returns_403_for_domain_mismatch_in_domain_dka_mode(): void
    {
        config(['dka.target_domain' => 'allowed.com']);

        $post = $this->makePost(['From' => 'intruder@otherdomain.com']);

        $result = $this->controller->receive($post, [], true);
        $this->assertEquals(403, $result->getStatusCode());
    }

    #[Test]
    public function it_returns_406_for_unrecognised_recipient(): void
    {
        $post = $this->makePost(['recipient' => 'unknown@dka.example.com']);

        $result = $this->controller->receive($post, [], true);
        $this->assertEquals(406, $result->getStatusCode());
    }

    // =========================================================================
    // Step 1 — Challenge request
    // =========================================================================

    #[Test]
    public function step1_issues_token_and_sends_email_when_dkim_passes(): void
    {
        $post = $this->makePost();

        $result = $this->controller->receive($post, [], true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($this->tokens->exists($this->senderEmail));

        $tokenData = $this->tokens->get($this->senderEmail);
        $this->assertEquals('email', $tokenData['channel']);

        Mail::assertSent(DkaMail::class);
    }

    #[Test]
    public function step1_sends_error_email_and_no_token_when_dkim_fails_verbose(): void
    {
        $post = $this->makePost(['X-Mailgun-Dkim-Check-Result' => 'Fail']);

        $result = $this->controller->receive($post, [], true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertFalse($this->tokens->exists($this->senderEmail));
        Mail::assertSent(DkaMail::class); // error email sent
    }

    #[Test]
    public function step1_sends_nothing_when_dkim_fails_terse(): void
    {
        $post = $this->makePost([
            'recipient'                   => 'no-reply@dka.example.com',
            'X-Mailgun-Dkim-Check-Result' => 'Fail',
        ]);

        $result = $this->controller->receive($post, [], true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertFalse($this->tokens->exists($this->senderEmail));
        Mail::assertNothingSent();
    }

    #[Test]
    public function step1_ignores_new_challenge_when_token_already_exists(): void
    {
        // Pre-create a token
        $existingToken = $this->tokens->create($this->senderEmail, 'email');

        $post = $this->makePost();
        $this->controller->receive($post, [], true);

        // Token should be unchanged
        $tokenData = $this->tokens->get($this->senderEmail);
        $this->assertEquals($existingToken, $tokenData['token']);
        Mail::assertNothingSent(); // no new token email sent
    }

    #[Test]
    public function step1_stores_rawmail_record(): void
    {
        $post = $this->makePost(['subject' => 'Hello']);

        $this->controller->receive($post, [], true);

        $this->assertEquals(1, Rawmail::count());
        $rawmail = Rawmail::first();
        $this->assertEquals($this->senderEmail, $rawmail->from_email);
        $this->assertEquals('Pass', $rawmail->dkim_check);
    }

    // =========================================================================
    // Step 2 — register (single)
    // =========================================================================

    #[Test]
    public function step2_register_stores_key_and_deletes_token(): void
    {
        [$secret, $public, $b64Public] = $this->generateKeyPair('ed25519');
        $token = $this->tokens->create($this->senderEmail, 'email');

        $payload = [
            'email_id'   => $this->senderEmail,
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => $b64Public,
            'metadata'   => [],
            'token'      => $token,
            'signature'  => $this->sign($this->senderEmail . '|' . $token, $secret),
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $result = $this->controller->receive($post, $files, true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertFalse($this->tokens->exists($this->senderEmail));
        $this->assertNotNull(PublicKey::findKey($this->senderEmail, 'default'));
    }

    #[Test]
    public function step2_register_fails_and_keeps_token_when_signature_is_wrong(): void
    {
        [$secret, $public, $b64Public] = $this->generateKeyPair('ed25519');
        $token = $this->tokens->create($this->senderEmail, 'email');

        $payload = [
            'email_id'   => $this->senderEmail,
            'selector'   => 'default',
            'algorithm'  => 'ed25519',
            'public_key' => $b64Public,
            'metadata'   => [],
            'token'      => $token,
            'signature'  => 'badsignature==',  // deliberately wrong
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $result = $this->controller->receive($post, $files, true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($this->tokens->exists($this->senderEmail)); // token survives
        $this->assertNull(PublicKey::findKey($this->senderEmail, 'default'));
    }

    #[Test]
    public function step2_register_rejects_selector_that_already_exists(): void
    {
        [$secret, $public, $b64Public] = $this->generateKeyPair('ed25519');
        $this->storeKey($this->senderEmail, 'default', $public, 'ed25519');

        $token = $this->tokens->create($this->senderEmail, 'email');
        $payload = [
            'email_id'   => $this->senderEmail,
            'selector'   => 'default', // already exists
            'algorithm'  => 'ed25519',
            'public_key' => $b64Public,
            'metadata'   => [],
            'token'      => $token,
            'signature'  => $this->sign($this->senderEmail . '|' . $token, $secret),
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $this->controller->receive($post, $files, true);

        $this->assertEquals(1, PublicKey::where('email_id', $this->senderEmail)->count()); // no extra row
    }

    // =========================================================================
    // Step 2 — register (batch)
    // =========================================================================

    #[Test]
    public function step2_batch_register_stores_multiple_keys_and_deletes_token(): void
    {
        [$sec1, $pub1, $b64pub1] = $this->generateKeyPair('ed25519');
        [$sec2, $pub2, $b64pub2] = $this->generateKeyPair('ed25519');
        $token = $this->tokens->create($this->senderEmail, 'email');
        $sig   = $this->senderEmail . '|' . $token;

        $batch = [
            [
                'email_id' => $this->senderEmail, 'selector' => 'default',
                'algorithm' => 'ed25519', 'public_key' => $b64pub1,
                'metadata' => [], 'token' => $token,
                'signature' => $this->sign($sig, $sec1),
            ],
            [
                'email_id' => $this->senderEmail, 'selector' => 'signing',
                'algorithm' => 'ed25519', 'public_key' => $b64pub2,
                'metadata' => [], 'token' => $token,
                'signature' => $this->sign($sig, $sec2),
            ],
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($batch));

        $result = $this->controller->receive($post, $files, true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertFalse($this->tokens->exists($this->senderEmail));
        $this->assertNotNull(PublicKey::findKey($this->senderEmail, 'default'));
        $this->assertNotNull(PublicKey::findKey($this->senderEmail, 'signing'));
    }

    #[Test]
    public function step2_batch_deletes_token_even_when_some_entries_fail(): void
    {
        [$sec1, $pub1, $b64pub1] = $this->generateKeyPair('ed25519');
        $token = $this->tokens->create($this->senderEmail, 'email');

        $batch = [
            [
                'email_id' => $this->senderEmail, 'selector' => 'good',
                'algorithm' => 'ed25519', 'public_key' => $b64pub1,
                'metadata' => [], 'token' => $token,
                'signature' => $this->sign($this->senderEmail . '|' . $token, $sec1),
            ],
            [
                'email_id' => $this->senderEmail, 'selector' => 'bad',
                'algorithm' => 'ed25519', 'public_key' => $b64pub1,
                'metadata' => [], 'token' => $token,
                'signature' => 'invalidsignature==', // this one will fail
            ],
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($batch));

        $this->controller->receive($post, $files, true);

        // Token deleted regardless
        $this->assertFalse($this->tokens->exists($this->senderEmail));
        // Good entry succeeded
        $this->assertNotNull(PublicKey::findKey($this->senderEmail, 'good'));
        // Bad entry did not get stored
        $this->assertNull(PublicKey::findKey($this->senderEmail, 'bad'));
    }

    // =========================================================================
    // Step 2 — modify
    // =========================================================================

    #[Test]
    public function step2_modify_replaces_key_with_valid_old_and_new_signatures(): void
    {
        [$oldSec, $oldPub, ] = $this->generateKeyPair('ed25519');
        [$newSec, $newPub, $b64NewPub] = $this->generateKeyPair('ed25519');
        $this->storeKey($this->senderEmail, 'default', $oldPub, 'ed25519');

        $token   = $this->tokens->create($this->senderEmail, 'email');
        $sigData = $this->senderEmail . '|' . $token;

        $payload = [
            'email_id'      => $this->senderEmail,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => $b64NewPub,
            'metadata'      => [],
            'token'         => $token,
            'old_signature' => $this->sign($sigData, $oldSec),
            'new_signature' => $this->sign($sigData, $newSec),
        ];

        $post  = $this->makePost(['subject' => 'modify', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $result = $this->controller->receive($post, $files, true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertFalse($this->tokens->exists($this->senderEmail));

        $stored = PublicKey::findKey($this->senderEmail, 'default');
        $this->assertEquals($newPub, $stored->public_key);
    }

    #[Test]
    public function step2_modify_fails_when_old_signature_is_wrong(): void
    {
        [$oldSec, $oldPub, ] = $this->generateKeyPair('ed25519');
        [$newSec, $newPub, $b64NewPub] = $this->generateKeyPair('ed25519');
        $this->storeKey($this->senderEmail, 'default', $oldPub, 'ed25519');

        $token   = $this->tokens->create($this->senderEmail, 'email');
        $sigData = $this->senderEmail . '|' . $token;

        $payload = [
            'email_id'      => $this->senderEmail,
            'selector'      => 'default',
            'algorithm'     => 'ed25519',
            'public_key'    => $b64NewPub,
            'metadata'      => [],
            'token'         => $token,
            'old_signature' => 'wrongsig==', // bad
            'new_signature' => $this->sign($sigData, $newSec),
        ];

        $post  = $this->makePost(['subject' => 'modify', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $this->controller->receive($post, $files, true);

        // Key should be unchanged
        $stored = PublicKey::findKey($this->senderEmail, 'default');
        $this->assertEquals($oldPub, $stored->public_key);
        $this->assertTrue($this->tokens->exists($this->senderEmail)); // token survives
    }

    // =========================================================================
    // Step 2 — delete
    // =========================================================================

    #[Test]
    public function step2_delete_removes_key_with_valid_signature(): void
    {
        [$sec, $pub, ] = $this->generateKeyPair('ed25519');
        $this->storeKey($this->senderEmail, 'default', $pub, 'ed25519');

        $token   = $this->tokens->create($this->senderEmail, 'email');
        $payload = [
            'email_id'  => $this->senderEmail,
            'selector'  => 'default',
            'token'     => $token,
            'signature' => $this->sign($this->senderEmail . '|' . $token, $sec),
        ];

        $post  = $this->makePost(['subject' => 'delete', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $result = $this->controller->receive($post, $files, true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertNull(PublicKey::findKey($this->senderEmail, 'default'));
        $this->assertFalse($this->tokens->exists($this->senderEmail));
    }

    // =========================================================================
    // Step 2 — dka-status=locked
    // =========================================================================

    #[Test]
    public function step2_lock_creates_dka_status_row_as_locked(): void
    {
        $token   = $this->tokens->create($this->senderEmail, 'email');
        $payload = ['email_id' => $this->senderEmail, 'token' => $token];

        $post  = $this->makePost(['subject' => 'dka-status=locked', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $result = $this->controller->receive($post, $files, true);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertFalse($this->tokens->exists($this->senderEmail));

        $status = PublicKey::findKey($this->senderEmail, 'dka-status');
        $this->assertNotNull($status);
        $meta = $status->getMetaArray();
        $this->assertEquals('locked', $meta['status']);
    }

    #[Test]
    public function step2_register_is_rejected_when_account_is_locked(): void
    {
        [$sec, $pub, $b64Pub] = $this->generateKeyPair('ed25519');

        // Lock the account
        PublicKey::create([
            'email_id'   => $this->senderEmail, 'selector' => 'dka-status',
            'algorithm'  => null, 'public_key' => null,
            'metadata'   => json_encode(['status' => 'locked']),
        ]);

        $token   = $this->tokens->create($this->senderEmail, 'email');
        $payload = [
            'email_id' => $this->senderEmail, 'selector' => 'default',
            'algorithm' => 'ed25519', 'public_key' => $b64Pub, 'metadata' => [],
            'token' => $token,
            'signature' => $this->sign($this->senderEmail . '|' . $token, $sec),
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $this->controller->receive($post, $files, true);

        $this->assertNull(PublicKey::findKey($this->senderEmail, 'default'));
    }

    // =========================================================================
    // Step 2 — dka-status=open
    // =========================================================================

    #[Test]
    public function step2_unlock_schedules_unlock_at_future_time(): void
    {
        // Create locked status
        PublicKey::create([
            'email_id'   => $this->senderEmail, 'selector' => 'dka-status',
            'algorithm'  => null, 'public_key' => null,
            'metadata'   => json_encode(['status' => 'locked']),
        ]);

        $token   = $this->tokens->create($this->senderEmail, 'email');
        $payload = ['email_id' => $this->senderEmail, 'token' => $token];

        $post  = $this->makePost(['subject' => 'dka-status=open', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $this->controller->receive($post, $files, true);

        $status = PublicKey::findKey($this->senderEmail, 'dka-status');
        $meta   = $status->getMetaArray();
        $this->assertEquals('locked', $meta['status']);
        $this->assertArrayHasKey('unlocks_at', $meta);

        // unlocks_at should be in the future
        $this->assertGreaterThan(now()->timestamp, \Carbon\Carbon::parse($meta['unlocks_at'])->timestamp);
    }

    #[Test]
    public function lazy_unlock_allows_operation_when_unlocks_at_is_past(): void
    {
        [$sec, $pub, $b64Pub] = $this->generateKeyPair('ed25519');

        // Create a locked status with unlocks_at in the past
        PublicKey::create([
            'email_id'   => $this->senderEmail, 'selector' => 'dka-status',
            'algorithm'  => null, 'public_key' => null,
            'metadata'   => json_encode([
                'status'     => 'locked',
                'unlocks_at' => now()->subMinute()->toIso8601String(),
            ]),
        ]);

        $token   = $this->tokens->create($this->senderEmail, 'email');
        $payload = [
            'email_id' => $this->senderEmail, 'selector' => 'default',
            'algorithm' => 'ed25519', 'public_key' => $b64Pub, 'metadata' => [],
            'token' => $token,
            'signature' => $this->sign($this->senderEmail . '|' . $token, $sec),
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        $this->controller->receive($post, $files, true);

        // Key registered despite prior locked status
        $this->assertNotNull(PublicKey::findKey($this->senderEmail, 'default'));

        // Status row lazily flipped to open
        $status = PublicKey::findKey($this->senderEmail, 'dka-status');
        $this->assertEquals('open', $status->getMetaArray()['status']);
    }

    // =========================================================================
    // File storage
    // =========================================================================

    #[Test]
    public function it_copies_attachment_file_to_rawmails_directory_in_test_mode(): void
    {
        $content = json_encode(['email_id' => $this->senderEmail, 'token' => 'x']);
        $token   = $this->tokens->create($this->senderEmail, 'email');

        $post = $this->makePost(['subject' => '', 'attachment-count' => '1']);
        // Use a real Step 1 so we don't need a valid command payload
        $post['subject'] = '';
        $files = $this->makeTempAttachment($content);

        $this->controller->receive($post, $files, true);

        // The rawmail record was created
        $rawmail = Rawmail::first();
        $this->assertNotNull($rawmail);

        // File should be copied into storage/app/rawmails/{rawmail->id}/
        $dest = storage_path('app/rawmails') . '/' . $rawmail->id;
        $this->assertDirectoryExists($dest);
        $this->assertCount(1, array_diff(scandir($dest), ['.', '..']));
    }

    // =========================================================================
    // Token channel isolation
    // =========================================================================

    #[Test]
    public function api_token_does_not_trigger_step2_email_flow(): void
    {
        [$sec, $pub, $b64Pub] = $this->generateKeyPair('ed25519');

        // Token was issued via API channel — should not be usable for email Step 2
        $this->tokens->create($this->senderEmail, 'api');

        $payload = [
            'email_id' => $this->senderEmail, 'selector' => 'default',
            'algorithm' => 'ed25519', 'public_key' => $b64Pub, 'metadata' => [],
            'token' => $this->tokens->get($this->senderEmail)['token'],
            'signature' => 'any',
        ];

        $post  = $this->makePost(['subject' => 'register', 'attachment-count' => '1']);
        $files = $this->makeTempAttachment(json_encode($payload));

        // Subject is 'register' but active token is api-channel, so treated as Step 1
        $this->controller->receive($post, $files, true);

        // No key stored — was treated as Step 1 (challenge), not Step 2
        $this->assertNull(PublicKey::findKey($this->senderEmail, 'default'));
    }
}
