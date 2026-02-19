<?php

namespace App\Services;

use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;

class TokenService
{
    /**
     * Redis key format: dka:token:{email_id}
     * Uses the 'dka' Redis connection which has no key prefix.
     */
    private function key(string $emailId): string
    {
        return 'dka:token:' . $emailId;
    }

    /**
     * Retrieve the token data for an email_id, or null if none exists.
     *
     * @return array{token: string, channel: string, created_at: string}|null
     */
    public function get(string $emailId): ?array
    {
        $raw = Redis::connection('dka')->get($this->key($emailId));
        return $raw ? json_decode($raw, true) : null;
    }

    /**
     * Check whether an active token exists for this email_id.
     */
    public function exists(string $emailId): bool
    {
        return (bool) Redis::connection('dka')->exists($this->key($emailId));
    }

    /**
     * Create a new token for the email_id with the given channel.
     * Overwrites any existing token.
     *
     * @param  string  $channel  'email' or 'api'
     * @return string  The generated token value
     */
    public function create(string $emailId, string $channel): string
    {
        $token = Str::random(40);
        $data  = [
            'token'      => $token,
            'channel'    => $channel,
            'created_at' => now()->toIso8601String(),
        ];

        Redis::connection('dka')->setex(
            $this->key($emailId),
            config('dka.token_ttl'),
            json_encode($data)
        );

        return $token;
    }

    /**
     * Delete the token for this email_id.
     */
    public function delete(string $emailId): void
    {
        Redis::connection('dka')->del($this->key($emailId));
    }

    /**
     * Return the remaining TTL in seconds, or null if no token exists.
     */
    public function ttl(string $emailId): ?int
    {
        $ttl = Redis::connection('dka')->ttl($this->key($emailId));
        return $ttl > 0 ? $ttl : null;
    }
}
