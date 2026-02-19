<?php

namespace Tests\Feature;

use App\Models\PublicKey;
use App\Services\CryptoService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * LookupController test suite.
 *
 * All tests use Laravel's HTTP test client (getJson) since the controller
 * depends on the Request object and the routes are plain public GET endpoints.
 *
 * Fixture keys are generated once per class via setUpBeforeClass() and reused
 * across tests for speed — key generation (especially RSA) is slow.
 */
class LookupControllerTest extends TestCase
{
    use RefreshDatabase;

    // Pre-generated key pairs shared across all tests
    protected static string $pubPem;
    protected static string $pubB64;
    protected static string $secPem;

    protected string $email = 'alice@example.com';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $crypto = new CryptoService();
        $pair   = $crypto->generateKeys('ed25519');

        static::$secPem = $pair->secret_key;
        static::$pubPem = $pair->public_key;
        static::$pubB64 = base64_encode($pair->public_key);
    }

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'dka.username'         => 'dka',
            'dka.terse'            => 'no-reply',
            'dka.domain'           => 'dka.example.com',
            'dka.target_domain'    => '*',
            'dka.version'          => 1,
            'dka.hidden_selectors' => ['dka-status', 'api'],
        ]);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    protected function storeKey(
        string $email,
        string $selector,
        ?string $publicKeyPem = null,
        ?string $algorithm = 'ed25519',
        array  $metadata = []
    ): PublicKey {
        return PublicKey::create([
            'email_id'   => $email,
            'selector'   => $selector,
            'algorithm'  => $algorithm,
            'public_key' => $publicKeyPem ?? static::$pubPem,
            'metadata'   => json_encode($metadata),
        ]);
    }

    // =========================================================================
    // GET /api/v1/lookup
    // =========================================================================

    #[Test]
    public function lookup_returns_422_when_email_is_missing(): void
    {
        $this->getJson('/api/v1/lookup')
            ->assertStatus(422)
            ->assertJsonFragment(['error' => 'email parameter is required']);
    }

    #[Test]
    public function lookup_returns_404_when_email_has_no_keys(): void
    {
        $this->getJson('/api/v1/lookup?email=nobody@example.com')
            ->assertStatus(404);
    }

    #[Test]
    public function lookup_returns_default_selector_when_no_selector_specified(): void
    {
        $this->storeKey($this->email, 'default');

        $response = $this->getJson('/api/v1/lookup?email=' . $this->email);

        $response->assertStatus(200)
            ->assertJsonFragment([
                'email_id'  => $this->email,
                'selector'  => 'default',
                'algorithm' => 'ed25519',
            ]);
    }

    #[Test]
    public function lookup_returns_named_selector_when_specified(): void
    {
        $this->storeKey($this->email, 'signing');

        $this->getJson('/api/v1/lookup?email=' . $this->email . '&selector=signing')
            ->assertStatus(200)
            ->assertJsonFragment(['selector' => 'signing']);
    }

    #[Test]
    public function lookup_returns_public_key_as_base64_encoded_pem(): void
    {
        $this->storeKey($this->email, 'default');

        $response = $this->getJson('/api/v1/lookup?email=' . $this->email);

        $data = $response->assertStatus(200)->json();
        $this->assertEquals(static::$pubB64, $data['public_key']);

        // Decodes back to the original PEM
        $this->assertEquals(static::$pubPem, base64_decode($data['public_key']));
    }

    #[Test]
    public function lookup_returns_metadata_as_decoded_object(): void
    {
        $this->storeKey($this->email, 'default', null, 'ed25519', ['purpose' => 'signing', 'version' => 2]);

        $response = $this->getJson('/api/v1/lookup?email=' . $this->email);

        $meta = $response->assertStatus(200)->json('metadata');
        $this->assertEquals('signing', $meta['purpose']);
        $this->assertEquals(2, $meta['version']);
    }

    #[Test]
    public function lookup_returns_404_for_dka_status_selector(): void
    {
        // Even if the row exists, it must not be returned
        $this->storeKey($this->email, 'dka-status', null, null, ['status' => 'locked']);

        $this->getJson('/api/v1/lookup?email=' . $this->email . '&selector=dka-status')
            ->assertStatus(404);
    }

    #[Test]
    public function lookup_returns_404_for_api_selector(): void
    {
        $this->storeKey($this->email, 'api');

        $this->getJson('/api/v1/lookup?email=' . $this->email . '&selector=api')
            ->assertStatus(404);
    }

    #[Test]
    public function lookup_returns_404_for_nonexistent_selector(): void
    {
        $this->storeKey($this->email, 'default');

        $this->getJson('/api/v1/lookup?email=' . $this->email . '&selector=nosuchselector')
            ->assertStatus(404);
    }

    #[Test]
    public function lookup_returns_403_for_email_outside_target_domain_in_dka_mode(): void
    {
        config(['dka.target_domain' => 'allowed.com']);

        $this->getJson('/api/v1/lookup?email=alice@other.com')
            ->assertStatus(403)
            ->assertJsonFragment(['error' => 'This DKA does not serve that domain']);
    }

    #[Test]
    public function lookup_allows_any_domain_in_rdka_mode(): void
    {
        config(['dka.target_domain' => '*']);
        $this->storeKey('alice@any-domain.io', 'default');

        $this->getJson('/api/v1/lookup?email=alice@any-domain.io')
            ->assertStatus(200);
    }

    #[Test]
    public function lookup_includes_updated_at_timestamp(): void
    {
        $this->storeKey($this->email, 'default');

        $response = $this->getJson('/api/v1/lookup?email=' . $this->email);

        $this->assertNotNull($response->json('updated_at'));
    }

    // =========================================================================
    // GET /api/v1/selectors
    // =========================================================================

    #[Test]
    public function selectors_returns_422_when_email_is_missing(): void
    {
        $this->getJson('/api/v1/selectors')
            ->assertStatus(422)
            ->assertJsonFragment(['error' => 'email parameter is required']);
    }

    #[Test]
    public function selectors_returns_404_when_email_has_no_public_keys(): void
    {
        $this->getJson('/api/v1/selectors?email=nobody@example.com')
            ->assertStatus(404);
    }

    #[Test]
    public function selectors_lists_all_visible_selectors(): void
    {
        $this->storeKey($this->email, 'default');
        $this->storeKey($this->email, 'signing');
        $this->storeKey($this->email, 'encrypt');

        $response = $this->getJson('/api/v1/selectors?email=' . $this->email);

        $response->assertStatus(200)
            ->assertJsonFragment(['email_id' => $this->email]);

        $selectors = $response->json('selectors');
        $this->assertContains('default', $selectors);
        $this->assertContains('signing', $selectors);
        $this->assertContains('encrypt', $selectors);
        $this->assertCount(3, $selectors);
    }

    #[Test]
    public function selectors_excludes_dka_status_selector(): void
    {
        $this->storeKey($this->email, 'default');
        $this->storeKey($this->email, 'dka-status', null, null, ['status' => 'locked']);

        $selectors = $this->getJson('/api/v1/selectors?email=' . $this->email)
            ->assertStatus(200)
            ->json('selectors');

        $this->assertNotContains('dka-status', $selectors);
        $this->assertContains('default', $selectors);
    }

    #[Test]
    public function selectors_excludes_api_selector(): void
    {
        $this->storeKey($this->email, 'default');
        $this->storeKey($this->email, 'api');

        $selectors = $this->getJson('/api/v1/selectors?email=' . $this->email)
            ->assertStatus(200)
            ->json('selectors');

        $this->assertNotContains('api', $selectors);
    }

    #[Test]
    public function selectors_returns_404_when_only_hidden_selectors_exist(): void
    {
        // Only dka-status stored — visible list is empty
        $this->storeKey($this->email, 'dka-status', null, null, ['status' => 'locked']);

        $this->getJson('/api/v1/selectors?email=' . $this->email)
            ->assertStatus(404);
    }

    #[Test]
    public function selectors_returns_403_for_email_outside_target_domain_in_dka_mode(): void
    {
        config(['dka.target_domain' => 'allowed.com']);

        $this->getJson('/api/v1/selectors?email=alice@other.com')
            ->assertStatus(403);
    }

    // =========================================================================
    // GET /api/v1/version
    // =========================================================================

    #[Test]
    public function version_returns_rdka_mode_when_target_domain_is_wildcard(): void
    {
        config(['dka.target_domain' => '*', 'dka.version' => 1, 'dka.domain' => 'dka.example.com']);

        $this->getJson('/api/v1/version')
            ->assertStatus(200)
            ->assertExactJson([
                'dka_version' => 1,
                'domain'      => 'dka.example.com',
                'mode'        => 'rdka',
            ]);
    }

    #[Test]
    public function version_returns_dka_mode_when_target_domain_is_set(): void
    {
        config(['dka.target_domain' => 'example.com', 'dka.version' => 1, 'dka.domain' => 'dka.example.com']);

        $this->getJson('/api/v1/version')
            ->assertStatus(200)
            ->assertJsonFragment(['mode' => 'dka']);
    }

    // =========================================================================
    // GET /api/v1/apis
    // =========================================================================

    #[Test]
    public function apis_returns_all_six_endpoints(): void
    {
        $response = $this->getJson('/api/v1/apis')->assertStatus(200);

        $endpoints = $response->json('endpoints');
        $this->assertCount(6, $endpoints);

        $paths = array_column($endpoints, 'path');
        $this->assertContains('/api/v1/lookup',    $paths);
        $this->assertContains('/api/v1/selectors', $paths);
        $this->assertContains('/api/v1/version',   $paths);
        $this->assertContains('/api/v1/apis',      $paths);
        $this->assertContains('/api/v1/challenge', $paths);
        $this->assertContains('/api/v1/submit',    $paths);
    }

    #[Test]
    public function apis_returns_correct_methods_for_each_endpoint(): void
    {
        $response  = $this->getJson('/api/v1/apis')->assertStatus(200);
        $endpoints = collect($response->json('endpoints'))->keyBy('path');

        $this->assertEquals('GET',  $endpoints['/api/v1/lookup']['method']);
        $this->assertEquals('GET',  $endpoints['/api/v1/selectors']['method']);
        $this->assertEquals('GET',  $endpoints['/api/v1/version']['method']);
        $this->assertEquals('GET',  $endpoints['/api/v1/apis']['method']);
        $this->assertEquals('POST', $endpoints['/api/v1/challenge']['method']);
        $this->assertEquals('POST', $endpoints['/api/v1/submit']['method']);
    }
}
