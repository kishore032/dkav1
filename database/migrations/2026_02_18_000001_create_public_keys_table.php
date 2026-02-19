<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('public_keys', function (Blueprint $table) {
            $table->id();
            $table->text('email_id');
            $table->text('selector');
            $table->text('algorithm')->nullable();
            $table->text('public_key')->nullable();
            $table->text('metadata')->nullable();
            $table->timestamps();

            $table->unique(['email_id', 'selector']);
        });

        // Additional index for fast email_id lookups
        \DB::statement('CREATE INDEX idx_public_keys_email_id ON public_keys(email_id)');
    }

    public function down(): void
    {
        Schema::dropIfExists('public_keys');
    }
};
