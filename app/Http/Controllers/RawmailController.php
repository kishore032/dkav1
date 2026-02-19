<?php

namespace App\Http\Controllers;

use App\Models\Rawmail;
use App\Services\DkaService;
use App\Services\TokenService;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;

class RawmailController extends Controller
{
    public function __construct(
        protected DkaService   $dka,
        protected TokenService $tokens,
    ) {}

    /**
     * Receive and process a Mailgun inbound webhook.
     *
     * In production (in_test_mode=false) this reads directly from $_POST and
     * $_FILES, bypassing Laravel's Request object which can mangle Mailgun's
     * multipart fields.  In test mode, callers supply $post and $files arrays
     * in the same shape as $_POST / $_FILES respectively.
     *
     * $files shape (matches PHP $_FILES):
     *   ['attachment-1' => ['name' => 'payload.json', 'tmp_name' => '/tmp/phpXXX', 'error' => 0, 'size' => N]]
     *
     * Returns an Illuminate\Http\Response so the route works and tests can
     * call ->getStatusCode() to assert the outcome.
     */
    public function receive($post = null, $files = null, bool $in_test_mode = false): Response
    {
        if (!$in_test_mode) {
            $post  = $_POST;
            $files = $_FILES;
        }

        // ------------------------------------------------------------------
        // 1. Basic payload sanity
        // ------------------------------------------------------------------
        if (!is_array($post)) {
            return response('Unacceptable', 406);
        }

        // ------------------------------------------------------------------
        // 2. Require Message-Id
        // ------------------------------------------------------------------
        $messageId = $post['Message-Id'] ?? $post['message-id'] ?? null;
        if (!$messageId) {
            return response('Missing Message-Id', 406);
        }

        // ------------------------------------------------------------------
        // 3. Deduplicate — return 200 immediately if already logged
        // ------------------------------------------------------------------
        if (Rawmail::where('message_id', $messageId)->exists()) {
            return response('OK', 200);
        }

        // ------------------------------------------------------------------
        // 4. Verify Mailgun webhook signature
        // ------------------------------------------------------------------
        $timestamp  = $post['timestamp']  ?? '';
        $mgToken    = $post['token']      ?? '';
        $signature  = $post['signature']  ?? '';
        $signingKey = config('dka.mg_signing_key');

        if ($signingKey) {
            $computed = hash_hmac('sha256', $timestamp . $mgToken, $signingKey);
            if (!hash_equals($computed, $signature)) {
                return response('Unauthorized', 401);
            }
        }

        // ------------------------------------------------------------------
        // 5. Parse From address
        // ------------------------------------------------------------------
        $fromRaw    = $post['From'] ?? $post['from'] ?? $post['sender'] ?? '';
        $fromParsed = eparse($fromRaw);
        if (!$fromParsed) {
            Log::warning('DKA: unparseable From', ['raw' => $fromRaw, 'message_id' => $messageId]);
            return response('Invalid From', 406);
        }

        // ------------------------------------------------------------------
        // 6. Domain check (domain DKA mode only)
        // ------------------------------------------------------------------
        $targetDomain = config('dka.target_domain');
        if ($targetDomain !== '*' && $fromParsed->domain !== $targetDomain) {
            Log::info('DKA: domain mismatch', ['from' => $fromParsed->domain, 'target' => $targetDomain]);
            return response('Domain not served', 403);
        }

        // ------------------------------------------------------------------
        // 7. Parse recipient — must be DKA_USERNAME or DKA_TERSE
        // ------------------------------------------------------------------
        $toRaw    = $post['recipient'] ?? $post['To'] ?? $post['to'] ?? '';
        $toParsed = eparse($toRaw);
        $dkaUser  = config('dka.username');
        $dkaTerse = config('dka.terse');

        if (!$toParsed || !in_array($toParsed->mailbox, [$dkaUser, $dkaTerse])) {
            Log::warning('DKA: unrecognised recipient', ['raw' => $toRaw]);
            return response('Invalid recipient', 406);
        }

        $verbose     = ($toParsed->mailbox === $dkaUser);
        $fromAddress = $toParsed->email; // outbound emails come from the DKA mailbox that received this

        // ------------------------------------------------------------------
        // 8. Collect headers
        // ------------------------------------------------------------------
        $dkimCheck       = $post['X-Mailgun-Dkim-Check-Result'] ?? '';
        $spfCheck        = $post['X-Mailgun-Spf']               ?? '';
        $spamFlag        = $post['X-Mailgun-Sflag']             ?? '';
        $subject         = $post['subject'] ?? $post['Subject'] ?? '';
        $attachmentCount = (int) ($post['attachment-count'] ?? 0);

        // ------------------------------------------------------------------
        // 9. Store rawmail record (append-only log)
        // ------------------------------------------------------------------
        $rawmail = Rawmail::create([
            'message_id'       => $messageId,
            'from_email'       => $fromParsed->email,
            'to_email'         => $toParsed->email,
            'subject'          => substr((string) $subject, 0, 1024),
            'timestamp'        => $timestamp,
            'spam_flag'        => $spamFlag,
            'dkim_check'       => $dkimCheck,
            'spf_check'        => $spfCheck,
            'attachment_count' => $attachmentCount,
        ]);

        // ------------------------------------------------------------------
        // 10. Store attachment files to disk
        //     Real mode:  move_uploaded_file() (PHP upload security check)
        //     Test mode:  copy()              (tmp file not a real upload)
        // ------------------------------------------------------------------
        $tempdir = storage_path('app/rawmails') . '/' . $rawmail->id . '/';

        if ($attachmentCount > 0 && !empty($files)) {
            if (!is_dir($tempdir)) {
                mkdir($tempdir, 0755, true);
            }

            foreach ($files as $fieldName => $file) {
                $tmpPath    = $file['tmp_name'] ?? null;
                $destName   = basename($tmpPath ?? '') ?: ($file['name'] ?? $fieldName);

                if (!$tmpPath || !file_exists($tmpPath)) {
                    continue;
                }

                if (!$in_test_mode) {
                    move_uploaded_file($tmpPath, $tempdir . $destName);
                } else {
                    copy($tmpPath, $tempdir . $destName);
                }
            }
        }

        // ------------------------------------------------------------------
        // 11. Route: Step 1 (challenge) vs Step 2 (submission)
        //
        //     Step 2 is triggered only when:
        //       - An email-channel token is active in Redis for this email_id
        //       - AND the subject is a recognised command
        //     Everything else is treated as Step 1.
        // ------------------------------------------------------------------
        $emailId       = $fromParsed->email;
        $tokenData     = $this->tokens->get($emailId);
        $hasEmailToken = $tokenData && ($tokenData['channel'] === 'email');

        $commandSubjects = ['register', 'modify', 'delete', 'dka-status=locked', 'dka-status=open'];
        $subjectNorm     = strtolower(trim((string) $subject));

        if ($hasEmailToken && in_array($subjectNorm, $commandSubjects)) {
            // Step 2 — parse JSON attachment and dispatch
            $payload = $this->readJsonAttachment($files);
            $this->dka->handleEmailSubmission($emailId, $subjectNorm, $payload, $verbose, $fromAddress);
        } else {
            // Step 1 — issue a verification token if DKIM passes
            $this->dka->handleEmailChallenge($emailId, $dkimCheck, $verbose, $fromAddress);
        }

        return response('OK', 200);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Read the first attachment (attachment-1) from the $files array and
     * decode its contents as JSON.
     *
     * Reads directly from tmp_name so no move/copy is required first.
     *
     * @param  array|null  $files  PHP $_FILES-shaped array
     * @return array|null  Decoded JSON or null on failure
     */
    private function readJsonAttachment(?array $files): ?array
    {
        $file    = $files['attachment-1'] ?? null;
        $tmpPath = $file['tmp_name']      ?? null;

        if (!$tmpPath || !file_exists($tmpPath)) {
            return null;
        }

        $content = file_get_contents($tmpPath);
        if ($content === false) {
            return null;
        }

        $decoded = json_decode($content, true);
        return is_array($decoded) ? $decoded : null;
    }
}
