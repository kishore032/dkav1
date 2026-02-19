<?php

namespace App\Services;

use App\Mail\DkaMail;
use App\Models\PublicKey;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class DkaService
{
    public function __construct(
        protected CryptoService $crypto,
        protected TokenService  $tokens,
    ) {}

    // -------------------------------------------------------------------------
    // Email flow — Step 1 (Challenge request)
    // -------------------------------------------------------------------------

    /**
     * Handle a Step 1 challenge request arriving via email.
     * Checks DKIM, issues a token, and sends it to the sender.
     *
     * @param  string  $emailId     Normalised sender email address
     * @param  string  $dkimResult  Value of X-Mailgun-Dkim-Check-Result header
     * @param  bool    $verbose     True if recipient was DKA_USERNAME
     * @param  string  $fromAddress Full DKA email address to send from
     */
    public function handleEmailChallenge(
        string $emailId,
        string $dkimResult,
        bool   $verbose,
        string $fromAddress
    ): void {
        if (strtolower($dkimResult) !== 'pass') {
            if ($verbose) {
                $this->sendEmail(
                    $emailId,
                    'DKA: DKIM Verification Failed',
                    "Your email did not pass DKIM verification and cannot be processed.\n\n"
                    . "Please ensure DKIM signing is enabled for your domain and try again.",
                    $fromAddress
                );
            }
            return;
        }

        // A token already exists — silently ignore per spec (§5.1)
        if ($this->tokens->exists($emailId)) {
            return;
        }

        $token = $this->tokens->create($emailId, 'email');
        $ttl   = config('dka.token_ttl');

        $body = "Your DKA verification token:\n\n"
            . "  {$token}\n\n"
            . "This token expires in {$ttl} seconds.\n\n"
            . "To complete your operation, send a new email to " . config('dka.username') . '@' . config('dka.domain') . "\n"
            . "with one of these subjects and a JSON attachment:\n\n"
            . "  Subject: register\n"
            . "  Subject: modify\n"
            . "  Subject: delete\n"
            . "  Subject: dka-status=locked\n"
            . "  Subject: dka-status=open\n";

        $this->sendEmail($emailId, 'DKA: Your Verification Token', $body, $fromAddress);
    }

    // -------------------------------------------------------------------------
    // Email flow — Step 2 (Command submission)
    // -------------------------------------------------------------------------

    /**
     * Handle a Step 2 email submission.
     * Routes to the correct command handler based on the email subject.
     *
     * @param  string      $emailId     Normalised sender email
     * @param  string      $subject     Email subject line
     * @param  array|null  $payload     Decoded JSON attachment, or null if missing/invalid
     * @param  bool        $verbose
     * @param  string      $fromAddress DKA email address to send from
     */
    public function handleEmailSubmission(
        string $emailId,
        string $subject,
        ?array $payload,
        bool   $verbose,
        string $fromAddress
    ): void {
        $subject = strtolower(trim($subject));

        if ($payload === null) {
            if ($verbose) {
                $this->sendEmail(
                    $emailId,
                    'DKA: Missing or Invalid Attachment',
                    "Your email required a JSON attachment but none was found or it was not valid JSON.",
                    $fromAddress
                );
            }
            return;
        }

        $result = match ($subject) {
            'register'          => $this->processRegister($emailId, $payload, 'email'),
            'modify'            => $this->processModify($emailId, $payload, 'email'),
            'delete'            => $this->processDelete($emailId, $payload, 'email'),
            'dka-status=locked' => $this->processLock($emailId, $payload, 'email'),
            'dka-status=open'   => $this->processUnlock($emailId, $payload, 'email'),
            default             => ['success' => false, 'error' => 'Unknown command: ' . $subject],
        };

        if ($verbose) {
            $this->sendResultEmail($emailId, $subject, $result, $fromAddress);
        }
    }

    // -------------------------------------------------------------------------
    // API flow — Challenge
    // -------------------------------------------------------------------------

    /**
     * Handle a POST /api/v1/challenge request.
     * Verifies the api-selector signature and issues a token.
     *
     * @return array{success: bool, token?: string, expires_in?: int, error?: string, code?: int}
     */
    public function handleApiChallenge(
        string $emailId,
        string $apiSignature,
        int    $unixTimestamp
    ): array {
        // Verify api selector exists
        $apiKey = PublicKey::findKey($emailId, 'api');
        if (!$apiKey) {
            return ['success' => false, 'error' => 'No api selector registered for this email.', 'code' => 403];
        }

        // Verify timestamp is within ±5 minutes of server time
        $now = time();
        if (abs($now - $unixTimestamp) > 300) {
            return ['success' => false, 'error' => 'Timestamp out of acceptable range (±5 minutes).', 'code' => 422];
        }

        // Verify api_signature: sign(email_id|unix_timestamp) with api private key
        $payload   = $emailId . '|' . $unixTimestamp;
        $storedPem = $apiKey->public_key;
        $valid     = $this->crypto->verifyRaw($payload, $apiSignature, $storedPem);

        if ($valid !== true) {
            return ['success' => false, 'error' => 'API signature verification failed.', 'code' => 401];
        }

        // Reject if a token already exists
        if ($this->tokens->exists($emailId)) {
            return ['success' => false, 'error' => 'A pending token already exists for this email.', 'code' => 409];
        }

        $token = $this->tokens->create($emailId, 'api');

        return [
            'success'    => true,
            'token'      => $token,
            'expires_in' => config('dka.token_ttl'),
        ];
    }

    // -------------------------------------------------------------------------
    // API flow — Submit
    // -------------------------------------------------------------------------

    /**
     * Handle a POST /api/v1/submit request.
     * Verifies api_signature then routes to the correct command handler.
     *
     * @return array{success: bool, message?: string, error?: string, code?: int}
     */
    public function handleApiSubmit(string $emailId, array $payload): array
    {
        $command = strtolower(trim($payload['command'] ?? ''));

        if (!in_array($command, ['register', 'modify', 'delete'])) {
            return ['success' => false, 'error' => 'Invalid or missing command. Allowed: register, modify, delete.', 'code' => 422];
        }

        // Verify api_signature: sign(email_id|token) with api private key
        $apiKey = PublicKey::findKey($emailId, 'api');
        if (!$apiKey) {
            return ['success' => false, 'error' => 'No api selector registered for this email.', 'code' => 403];
        }

        $token        = $payload['token'] ?? '';
        $apiSignature = $payload['api_signature'] ?? '';
        $sigPayload   = $emailId . '|' . $token;
        $valid        = $this->crypto->verifyRaw($sigPayload, $apiSignature, $apiKey->public_key);

        if ($valid !== true) {
            return ['success' => false, 'error' => 'API signature verification failed.', 'code' => 401];
        }

        return match ($command) {
            'register' => $this->processRegister($emailId, $payload, 'api'),
            'modify'   => $this->processModify($emailId, $payload, 'api'),
            'delete'   => $this->processDelete($emailId, $payload, 'api'),
        };
    }

    // -------------------------------------------------------------------------
    // Command processors (shared by email and API flows)
    // -------------------------------------------------------------------------

    /**
     * Process a register command (single or batch).
     * Batch is an indexed array; single is an associative array.
     */
    public function processRegister(string $emailId, array $payload, string $channel): array
    {
        // Batch: array of objects
        if (isset($payload[0]) && is_array($payload[0])) {
            return $this->processBatchRegister($emailId, $payload, $channel);
        }

        // Single
        return $this->doRegister($emailId, $payload, $channel);
    }

    private function processBatchRegister(string $emailId, array $items, string $channel): array
    {
        $token = $items[0]['token'] ?? null;

        // Validate shared token and email_id before processing entries
        $tokenData = $this->validateToken($emailId, $token, $channel);
        if (!$tokenData['valid']) {
            return ['success' => false, 'error' => $tokenData['error']];
        }

        $results = [];
        foreach ($items as $i => $entry) {
            if (($entry['email_id'] ?? '') !== $emailId) {
                $results[] = ['selector' => $entry['selector'] ?? "item_{$i}", 'success' => false, 'error' => 'email_id mismatch'];
                continue;
            }
            if (($entry['token'] ?? '') !== $token) {
                $results[] = ['selector' => $entry['selector'] ?? "item_{$i}", 'success' => false, 'error' => 'Token mismatch across batch entries'];
                continue;
            }
            $r = $this->doRegisterEntry($emailId, $entry);
            $results[] = array_merge(['selector' => $entry['selector'] ?? "item_{$i}"], $r);
        }

        // Delete token after batch regardless of individual outcomes (§8.2)
        $this->tokens->delete($emailId);

        $allOk = collect($results)->every(fn ($r) => $r['success'] ?? false);
        return ['success' => $allOk, 'batch' => true, 'results' => $results];
    }

    private function doRegister(string $emailId, array $data, string $channel): array
    {
        $token = $data['token'] ?? null;

        $tokenData = $this->validateToken($emailId, $token, $channel);
        if (!$tokenData['valid']) {
            return ['success' => false, 'error' => $tokenData['error']];
        }

        if (!$this->checkLockStatus($emailId)) {
            return ['success' => false, 'error' => 'Account is locked. Send dka-status=open to unlock.'];
        }

        $result = $this->doRegisterEntry($emailId, $data);

        if ($result['success']) {
            $this->tokens->delete($emailId);
        }

        return $result;
    }

    /**
     * Validate and store a single key entry. Does NOT touch the token.
     */
    private function doRegisterEntry(string $emailId, array $data): array
    {
        $selector  = strtolower(trim($data['selector'] ?? ''));
        $algorithm = strtolower(trim($data['algorithm'] ?? ''));
        $b64Key    = $data['public_key'] ?? '';
        $metadata  = $data['metadata'] ?? null;
        $signature = $data['signature'] ?? '';
        $token     = $data['token'] ?? '';

        // Validate selector format
        if (!$this->isValidSelector($selector)) {
            return ['success' => false, 'error' => "Invalid selector '{$selector}'. Must be lowercase alphanumeric, max 32 chars."];
        }

        // Hidden selectors cannot be registered via register command
        if (in_array($selector, PublicKey::HIDDEN_SELECTORS)) {
            return ['success' => false, 'error' => "Selector '{$selector}' is reserved."];
        }

        // Selector must not already exist
        if (PublicKey::findKey($emailId, $selector)) {
            return ['success' => false, 'error' => "Selector '{$selector}' already exists. Use modify to update."];
        }

        // Decode and validate public key
        $pem = base64_decode($b64Key, true);
        if ($pem === false) {
            return ['success' => false, 'error' => 'public_key is not valid base64.'];
        }

        $detectedAlgo = $this->crypto->detectAlgorithm($pem);
        if ($detectedAlgo === null) {
            return ['success' => false, 'error' => 'public_key is not a recognised PKCS#8 key.'];
        }
        if ($detectedAlgo !== $algorithm) {
            return ['success' => false, 'error' => "Algorithm mismatch: declared '{$algorithm}', detected '{$detectedAlgo}'."];
        }

        // Verify signature: sign(email_id|token) with the submitted key
        $sigPayload = $emailId . '|' . $token;
        $valid      = $this->crypto->verifyRaw($sigPayload, $signature, $pem);
        if ($valid !== true) {
            return ['success' => false, 'error' => 'Signature verification failed.'];
        }

        PublicKey::create([
            'email_id'   => $emailId,
            'selector'   => $selector,
            'algorithm'  => $algorithm,
            'public_key' => $pem,
            'metadata'   => is_array($metadata) ? json_encode($metadata) : ($metadata ?? '{}'),
        ]);

        return ['success' => true, 'message' => "Selector '{$selector}' registered."];
    }

    private function processModify(string $emailId, array $data, string $channel): array
    {
        $token = $data['token'] ?? null;

        $tokenData = $this->validateToken($emailId, $token, $channel);
        if (!$tokenData['valid']) {
            return ['success' => false, 'error' => $tokenData['error']];
        }

        if (!$this->checkLockStatus($emailId)) {
            return ['success' => false, 'error' => 'Account is locked. Send dka-status=open to unlock.'];
        }

        $selector     = strtolower(trim($data['selector'] ?? ''));
        $algorithm    = strtolower(trim($data['algorithm'] ?? ''));
        $b64NewKey    = $data['public_key'] ?? '';
        $metadata     = $data['metadata'] ?? null;
        $oldSignature = $data['old_signature'] ?? '';
        $newSignature = $data['new_signature'] ?? '';

        if (!$this->isValidSelector($selector)) {
            return ['success' => false, 'error' => "Invalid selector '{$selector}'."];
        }

        if (in_array($selector, PublicKey::HIDDEN_SELECTORS)) {
            return ['success' => false, 'error' => "Selector '{$selector}' is reserved."];
        }

        $existing = PublicKey::findKey($emailId, $selector);
        if (!$existing) {
            return ['success' => false, 'error' => "Selector '{$selector}' does not exist. Use register to create it."];
        }

        // Decode and validate new public key
        $newPem = base64_decode($b64NewKey, true);
        if ($newPem === false) {
            return ['success' => false, 'error' => 'public_key is not valid base64.'];
        }

        $detectedAlgo = $this->crypto->detectAlgorithm($newPem);
        if ($detectedAlgo === null) {
            return ['success' => false, 'error' => 'public_key is not a recognised PKCS#8 key.'];
        }
        if ($detectedAlgo !== $algorithm) {
            return ['success' => false, 'error' => "Algorithm mismatch: declared '{$algorithm}', detected '{$detectedAlgo}'."];
        }

        $sigPayload = $emailId . '|' . $token;

        // Verify old_signature against the stored (current) key
        $oldValid = $this->crypto->verifyRaw($sigPayload, $oldSignature, $existing->public_key);
        if ($oldValid !== true) {
            return ['success' => false, 'error' => 'old_signature verification failed against existing key.'];
        }

        // Verify new_signature against the submitted (new) key
        $newValid = $this->crypto->verifyRaw($sigPayload, $newSignature, $newPem);
        if ($newValid !== true) {
            return ['success' => false, 'error' => 'new_signature verification failed against new key.'];
        }

        $existing->update([
            'algorithm'  => $algorithm,
            'public_key' => $newPem,
            'metadata'   => is_array($metadata) ? json_encode($metadata) : ($metadata ?? $existing->metadata),
        ]);

        $this->tokens->delete($emailId);

        return ['success' => true, 'message' => "Selector '{$selector}' updated."];
    }

    private function processDelete(string $emailId, array $data, string $channel): array
    {
        $token = $data['token'] ?? null;

        $tokenData = $this->validateToken($emailId, $token, $channel);
        if (!$tokenData['valid']) {
            return ['success' => false, 'error' => $tokenData['error']];
        }

        if (!$this->checkLockStatus($emailId)) {
            return ['success' => false, 'error' => 'Account is locked. Send dka-status=open to unlock.'];
        }

        $selector  = strtolower(trim($data['selector'] ?? ''));
        $signature = $data['signature'] ?? '';

        if (!$this->isValidSelector($selector)) {
            return ['success' => false, 'error' => "Invalid selector '{$selector}'."];
        }

        if (in_array($selector, PublicKey::HIDDEN_SELECTORS)) {
            return ['success' => false, 'error' => "Selector '{$selector}' is reserved."];
        }

        $existing = PublicKey::findKey($emailId, $selector);
        if (!$existing) {
            return ['success' => false, 'error' => "Selector '{$selector}' does not exist."];
        }

        // Verify signature against stored key
        $sigPayload = $emailId . '|' . $token;
        $valid      = $this->crypto->verifyRaw($sigPayload, $signature, $existing->public_key);
        if ($valid !== true) {
            return ['success' => false, 'error' => 'Signature verification failed.'];
        }

        $existing->delete();
        $this->tokens->delete($emailId);

        return ['success' => true, 'message' => "Selector '{$selector}' deleted."];
    }

    /**
     * Lock the account. No signature required — email DKIM + token is sufficient.
     * Email channel only.
     */
    private function processLock(string $emailId, array $data, string $channel): array
    {
        if ($channel !== 'email') {
            return ['success' => false, 'error' => 'dka-status=locked is only available via the email channel.'];
        }

        $token     = $data['token'] ?? null;
        $tokenData = $this->validateToken($emailId, $token, $channel);
        if (!$tokenData['valid']) {
            return ['success' => false, 'error' => $tokenData['error']];
        }

        // Edge case: if unlock is already pending, ignore the lock request (§8.6)
        $statusRow = PublicKey::findKey($emailId, 'dka-status');
        if ($statusRow) {
            $meta = $statusRow->getMetaArray();
            if (($meta['status'] ?? '') === 'locked' && isset($meta['unlocks_at'])) {
                $this->tokens->delete($emailId);
                return ['success' => true, 'message' => 'An unlock is already pending; lock request ignored.'];
            }
        }

        $newMeta = json_encode(['status' => 'locked']);

        if ($statusRow) {
            $statusRow->update(['metadata' => $newMeta]);
        } else {
            PublicKey::create([
                'email_id'  => $emailId,
                'selector'  => 'dka-status',
                'algorithm' => null,
                'public_key' => null,
                'metadata'  => $newMeta,
            ]);
        }

        $this->tokens->delete($emailId);

        return ['success' => true, 'message' => 'Account locked. Only dka-status=open will be accepted.'];
    }

    /**
     * Schedule an account unlock after DKA_UNLOCK_DELAY minutes.
     * Email channel only.
     */
    private function processUnlock(string $emailId, array $data, string $channel): array
    {
        if ($channel !== 'email') {
            return ['success' => false, 'error' => 'dka-status=open is only available via the email channel.'];
        }

        $token     = $data['token'] ?? null;
        $tokenData = $this->validateToken($emailId, $token, $channel);
        if (!$tokenData['valid']) {
            return ['success' => false, 'error' => $tokenData['error']];
        }

        $unlockDelay = config('dka.unlock_delay'); // minutes
        $unlocksAt   = now()->addMinutes($unlockDelay)->toIso8601String();

        $statusRow = PublicKey::findKey($emailId, 'dka-status');
        $newMeta   = json_encode(['status' => 'locked', 'unlocks_at' => $unlocksAt]);

        if ($statusRow) {
            $statusRow->update(['metadata' => $newMeta]);
        } else {
            PublicKey::create([
                'email_id'   => $emailId,
                'selector'   => 'dka-status',
                'algorithm'  => null,
                'public_key' => null,
                'metadata'   => $newMeta,
            ]);
        }

        $this->tokens->delete($emailId);

        return [
            'success'    => true,
            'message'    => "Your account will be unlocked at {$unlocksAt}.",
            'unlocks_at' => $unlocksAt,
        ];
    }

    // -------------------------------------------------------------------------
    // Lock status helper
    // -------------------------------------------------------------------------

    /**
     * Returns true if operations are permitted for this email_id.
     * Lazily flips status to 'open' when unlocks_at is in the past.
     */
    public function checkLockStatus(string $emailId): bool
    {
        $statusRow = PublicKey::findKey($emailId, 'dka-status');

        if (!$statusRow) {
            return true; // No row = open
        }

        $meta   = $statusRow->getMetaArray();
        $status = $meta['status'] ?? 'open';

        if ($status === 'open') {
            return true;
        }

        // Locked — check for scheduled unlock
        if (isset($meta['unlocks_at'])) {
            $unlocksAt = Carbon::parse($meta['unlocks_at']);
            if ($unlocksAt->isPast()) {
                // Lazily flip to open
                $statusRow->update(['metadata' => json_encode(['status' => 'open'])]);
                return true;
            }
        }

        return false; // Still locked
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Validate that a token exists in Redis, matches the given value,
     * and was issued for the correct channel.
     *
     * @return array{valid: bool, error?: string}
     */
    private function validateToken(string $emailId, ?string $token, string $channel): array
    {
        $stored = $this->tokens->get($emailId);

        if (!$stored) {
            return ['valid' => false, 'error' => 'No active token found. Send a new email to request a challenge.'];
        }

        if ($stored['channel'] !== $channel) {
            return ['valid' => false, 'error' => "Token was issued for the '{$stored['channel']}' channel, not '{$channel}'."];
        }

        if ($stored['token'] !== $token) {
            return ['valid' => false, 'error' => 'Token value does not match. Token survives until expiry; try again.'];
        }

        return ['valid' => true];
    }

    /**
     * Validate selector format: lowercase alphanumeric (hyphen allowed), max 32 chars.
     */
    private function isValidSelector(string $selector): bool
    {
        return (bool) preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/', $selector);
    }

    /**
     * Send a plain-text email.
     *
     * @param  string  $to          Recipient address
     * @param  string  $subject     Email subject
     * @param  string  $body        Plain-text body
     * @param  string  $fromAddress Full from address (e.g. dka@dka.example.com)
     */
    private function sendEmail(string $to, string $subject, string $body, string $fromAddress): void
    {
        try {
            Mail::to($to)->send(new DkaMail($fromAddress, $subject, $body));
        } catch (\Exception $e) {
            Log::error('DKA: failed to send email', [
                'to'      => $to,
                'subject' => $subject,
                'error'   => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send an acknowledgement or error email after a command result.
     */
    private function sendResultEmail(
        string $emailId,
        string $command,
        array  $result,
        string $fromAddress
    ): void {
        if ($result['success']) {
            $subject = 'DKA: ' . ucfirst($command) . ' Successful';
            $body    = $result['message'] ?? 'Operation completed successfully.';

            // Include batch results if present
            if (!empty($result['batch']) && !empty($result['results'])) {
                $lines = [];
                foreach ($result['results'] as $r) {
                    $status  = $r['success'] ? 'OK' : 'FAILED';
                    $detail  = $r['message'] ?? $r['error'] ?? '';
                    $lines[] = "  [{$status}] {$r['selector']}: {$detail}";
                }
                $body .= "\n\nBatch results:\n" . implode("\n", $lines);
            }

            if (isset($result['unlocks_at'])) {
                $body .= "\n\nUnlock scheduled at: {$result['unlocks_at']}";
            }
        } else {
            $subject = 'DKA: ' . ucfirst($command) . ' Failed';
            $body    = 'Error: ' . ($result['error'] ?? 'Unknown error.');
        }

        $this->sendEmail($emailId, $subject, $body, $fromAddress);
    }
}
