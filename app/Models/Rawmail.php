<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Rawmail extends Model
{
    /**
     * Append-only inbound email log.
     * Records are written once on receipt and never updated.
     */

    protected $fillable = [
        'message_id',
        'from_email',
        'to_email',
        'subject',
        'timestamp',
        'spam_flag',
        'dkim_check',
        'spf_check',
        'attachment_count',
    ];

    protected $casts = [
        'attachment_count' => 'integer',
    ];
}
