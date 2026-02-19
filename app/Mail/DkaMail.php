<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class DkaMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public readonly string $fromAddress,
        public readonly string $emailSubject,
        public readonly string $messageBody,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            from: $this->fromAddress,
            subject: $this->emailSubject,
        );
    }

    public function content(): Content
    {
        return new Content(
            text: 'emails.dka',
        );
    }
}
