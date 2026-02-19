<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('rawmails', function (Blueprint $table) {
            $table->id();
            $table->text('message_id')->unique();
            $table->text('from_email');
            $table->text('to_email');
            $table->text('subject')->nullable();
            $table->text('timestamp')->nullable();
            $table->text('spam_flag')->nullable();
            $table->text('dkim_check')->nullable();
            $table->text('spf_check')->nullable();
            $table->integer('attachment_count')->default(0);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('rawmails');
    }
};
