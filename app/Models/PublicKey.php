<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PublicKey extends Model
{
    /**
     * Public key store.
     *
     * Hidden selectors (dka-status, api) are stored here but never
     * returned by the public lookup or selectors API.
     */

    protected $fillable = [
        'email_id',
        'selector',
        'algorithm',
        'public_key',
        'metadata',
    ];

    /**
     * Selectors that are internal to the DKA and never exposed publicly.
     */
    public const HIDDEN_SELECTORS = ['dka-status', 'api'];

    /**
     * Find a key row by email_id + selector.
     */
    public static function findKey(string $emailId, string $selector): ?self
    {
        return self::where('email_id', $emailId)
            ->where('selector', $selector)
            ->first();
    }

    /**
     * Decode the metadata JSON field into an array.
     */
    public function getMetaArray(): array
    {
        return json_decode($this->metadata ?? '{}', true) ?? [];
    }
}
