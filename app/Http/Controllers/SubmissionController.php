<?php

namespace App\Http\Controllers;

use App\Services\DkaService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SubmissionController extends Controller
{
    public function __construct(protected DkaService $dka) {}

    // -------------------------------------------------------------------------
    // POST /api/v1/challenge
    // -------------------------------------------------------------------------

    /**
     * Request a token for subsequent API submission.
     *
     * Body:
     *   email_id        string  required
     *   api_signature   string  required  sign(email_id|unix_timestamp) with api key
     *   unix_timestamp  int     required
     */
    public function challenge(Request $request): JsonResponse
    {
        $emailId       = strtolower(trim($request->input('email_id', '')));
        $apiSignature  = $request->input('api_signature', '');
        $unixTimestamp = (int) $request->input('unix_timestamp', 0);

        if (!$emailId) {
            return response()->json(['error' => 'email_id is required'], 422);
        }
        if (!$apiSignature) {
            return response()->json(['error' => 'api_signature is required'], 422);
        }
        if (!$unixTimestamp) {
            return response()->json(['error' => 'unix_timestamp is required'], 422);
        }

        // Domain check for non-rDKA mode
        $domainCheck = $this->checkEmailDomain($emailId);
        if ($domainCheck) {
            return $domainCheck;
        }

        $result = $this->dka->handleApiChallenge($emailId, $apiSignature, $unixTimestamp);

        if (!$result['success']) {
            return response()->json(
                ['error' => $result['error']],
                $result['code'] ?? 422
            );
        }

        return response()->json([
            'token'      => $result['token'],
            'expires_in' => $result['expires_in'],
        ]);
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/submit
    // -------------------------------------------------------------------------

    /**
     * Submit a key operation (register, modify, delete).
     *
     * All requests require:
     *   email_id       string  required
     *   command        string  required  register | modify | delete
     *   token          string  required  from /challenge
     *   api_signature  string  required  sign(email_id|token) with api key
     *
     * Additional fields depend on command (see design doc §9.2).
     */
    public function submit(Request $request): JsonResponse
    {
        $emailId = strtolower(trim($request->input('email_id', '')));

        if (!$emailId) {
            return response()->json(['error' => 'email_id is required'], 422);
        }

        // Domain check for non-rDKA mode
        $domainCheck = $this->checkEmailDomain($emailId);
        if ($domainCheck) {
            return $domainCheck;
        }

        $payload = $request->all();
        $payload['email_id'] = $emailId;

        $result = $this->dka->handleApiSubmit($emailId, $payload);

        if (!$result['success']) {
            return response()->json(
                ['error' => $result['error']],
                $result['code'] ?? 422
            );
        }

        return response()->json(['message' => $result['message']]);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * In Domain DKA mode, reject requests for email addresses outside the target domain.
     */
    private function checkEmailDomain(string $email): ?JsonResponse
    {
        $targetDomain = config('dka.target_domain');
        if ($targetDomain === '*') {
            return null;
        }

        $parsed = eparse($email);
        if (!$parsed || $parsed->domain !== $targetDomain) {
            return response()->json(['error' => 'This DKA does not serve that domain'], 403);
        }

        return null;
    }
}
