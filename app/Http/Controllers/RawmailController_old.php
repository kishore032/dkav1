<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use App\Models\Rawmail;

// use App\Events\NewRawmail;
// use Webklex\IMAP\Client;
// use App\Sender;
// use App\Models\Inmail;
// use App\Models\InmailAttachment;

use Illuminate\Http\Request;

class RawmailController extends Controller
{
    public static function receivemail ($post=null, $files=null, $in_test_mode=false)
    {
        if (!$in_test_mode) {
            $post = $_POST;
            $files = $_FILES;
        }
        if (!is_array($post)) return 406;                          // Unacceptable data - don't retry
        if (Rawmail::where('message_id', $post['Message-Id'])->first()) return 200;
        $token = $post['token'] ?? '';
        $timestamp = $post['timestamp'] ?? '';
        $signature = $post['signature'] ?? '';
        if (hash_hmac('sha256', $timestamp . $token, env('MG_SIGNING_KEY')) != $signature) return 401;
        $to = array_key_exists('To', $post) ? substr($post['To'], 0, 1024) : '';
        $subject = array_key_exists('Subject', $post) ? substr($post['Subject'], 0, 1024) : '';
        $r = Rawmail::create(['message_id' => $post['Message-Id'],
                                'from' => $post['From'] ?? null,
                                'to' => $to,
                                'subject' => $subject,
                                'recipient' => $post['recipient'] ?? null,
                                'timestamp' => $timestamp,
                                'token' => $token,
                                'signature' => $signature,
                                'body_html' => array_key_exists('body-html', $post),
                                'body_plain' => array_key_exists('body-plain', $post),
                                'content_id_map' => $post['content-id-map'] ?? null,
                ]);
        $rawmail_id = $r->id;
        $r->rawstore($post, $files);
        $tempdir=storage_path('rawmail') . '/' . $rawmail_id . '/';           // both abs path and Storage facade are used - see note below
        if ($r->body_plain) {
            Storage::disk('rawmail')->put($rawmail_id . '/body_plain.txt', $post['body-plain']);
        }
        if ($r->body_html) {
            Storage::disk('rawmail')->put($rawmail_id . '/body_html.html', $post['body-html']);
        }
        if (!empty($files)) {
            $r->attachment_filemap = $files;
            $r->attachment_count = count($files);
            foreach ($files as $file) {
            $tmp_path=($file['tmp_name']);
            $tmp_file_name=basename($tmp_path);
            if (!$in_test_mode) move_uploaded_file ($tmp_path, $tempdir . $tmp_file_name);
            else copy($tmp_path, $tempdir . $tmp_file_name);
            }
            if (array_key_exists('content-id-map', $post)) $r->content_id_map = json_decode($post['content-id-map'], true);
                        // see notes below on this Content-Disposition hack.
            if (array_key_exists('Content-Disposition', $post)) {
            $tmp_path = $files['attachment-1']['tmp_name'] ?? null;
            $tmp_file_name = basename($tmp_path) ?? null;
            $r->content_id_map = [$tmp_file_name => 'attachment-1'];
            Storage::disk('rawmail')->put($rawmail_id . '/body_html.html', "<img src='cid:" . $tmp_file_name . "'>");
            $r->body_html = true;
            }
        }

        $r->save();

        if (eparse($r->recipient)->mailbox == env('MAILBOT')) {
            $r->processBotmail();
            return response('OK', 200);
        } else {
            epLog('NewRawmail Event Handler', 'Sending for Processing', 'ID: ' . $r->id, null, 1);
            $result = $r->processRawmail();
            epLog('NewRawmail Event Handler', 'Rawmail Processed', 'ID: ' . $r->id, 'Status: ' . 200, 3);
            return $result ? response('OK', 200) : response('Invalid data', 400);
        }
    }
}
