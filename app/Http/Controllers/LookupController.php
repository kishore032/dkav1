<?php

namespace App\Http\Controllers;

use App\Models\PublicKey;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class LookupController extends Controller
{
    // -------------------------------------------------------------------------
    // GET /api/v1/lookup?email={email_id}[&selector={selector}]
    // -------------------------------------------------------------------------

    public function lookup(Request $request): JsonResponse
    {
        $email    = strtolower(trim($request->query('email', '')));
        $selector = strtolower(trim($request->query('selector', 'default')));

        if (!$email) {
            return response()->json(['error' => 'email parameter is required'], 422);
        }

        // Domain check for non-rDKA mode
        $domainCheck = $this->checkEmailDomain($email);
        if ($domainCheck) {
            return $domainCheck;
        }

        // Hidden selectors return 404 (do not leak existence)
        if (in_array($selector, config('dka.hidden_selectors', []))) {
            return response()->json(['error' => 'Not found'], 404);
        }

        $row = PublicKey::findKey($email, $selector);
        if (!$row) {
            return response()->json(['error' => 'Not found'], 404);
        }

        return response()->json([
            'email_id'   => $row->email_id,
            'selector'   => $row->selector,
            'algorithm'  => $row->algorithm,
            'public_key' => $row->public_key ? base64_encode($row->public_key) : null,
            'metadata'   => json_decode($row->metadata ?? '{}'),
            'updated_at' => $row->updated_at?->toIso8601String(),
        ]);
    }

    // -------------------------------------------------------------------------
    // GET /api/v1/selectors?email={email_id}
    // -------------------------------------------------------------------------

    public function selectors(Request $request): JsonResponse
    {
        $email = strtolower(trim($request->query('email', '')));

        if (!$email) {
            return response()->json(['error' => 'email parameter is required'], 422);
        }

        $domainCheck = $this->checkEmailDomain($email);
        if ($domainCheck) {
            return $domainCheck;
        }

        $hidden = config('dka.hidden_selectors', []);

        $selectors = PublicKey::where('email_id', $email)
            ->whereNotIn('selector', $hidden)
            ->pluck('selector')
            ->values()
            ->all();

        if (empty($selectors)) {
            return response()->json(['error' => 'Not found'], 404);
        }

        return response()->json([
            'email_id'  => $email,
            'selectors' => $selectors,
        ]);
    }

    // -------------------------------------------------------------------------
    // GET /api/v1/version
    // -------------------------------------------------------------------------

    public function version(): JsonResponse
    {
        $targetDomain = config('dka.target_domain');
        $mode         = ($targetDomain === '*') ? 'rdka' : 'dka';

        return response()->json([
            'dka_version' => config('dka.version'),
            'domain'      => config('dka.domain'),
            'mode'        => $mode,
        ]);
    }

    // -------------------------------------------------------------------------
    // GET /api/v1/apis
    // -------------------------------------------------------------------------

    public function apis(): JsonResponse
    {
        return response()->json([
            'endpoints' => [
                ['method' => 'GET',  'path' => '/api/v1/lookup',    'params' => ['email', 'selector?']],
                ['method' => 'GET',  'path' => '/api/v1/selectors', 'params' => ['email']],
                ['method' => 'GET',  'path' => '/api/v1/version',   'params' => []],
                ['method' => 'GET',  'path' => '/api/v1/apis',      'params' => []],
                ['method' => 'POST', 'path' => '/api/v1/challenge', 'params' => []],
                ['method' => 'POST', 'path' => '/api/v1/submit',    'params' => []],
            ],
        ]);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * In Domain DKA mode, reject lookups for email addresses outside the target domain.
     * Returns a JsonResponse on failure, or null if the check passes.
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
