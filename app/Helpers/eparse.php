<?php

define('EMAIL_NAME', '(?!\.)(?!.*\.\.)[A-Za-z0-9._%+-]+(?<!\.)'); // '(.*)');
define('MAILBOX', '\s*([a-z][a-z0-9\'-.]*)\s*');
define('HOST', '([a-z][a-z0-9-]*\.)*([a-z][a-z0-9-]+\.[a-z]+)');

/**
 * Parse an RFC 5322 email address string into its components.
 *
 * Handles both bare addresses (user@example.com) and display-name
 * format (Display Name <user@example.com>).
 *
 * @param  mixed  $rfc
 * @return object|null  {name, mailbox, host, email, domain} or null on failure
 */
function eparse($rfc): ?object
{
    if (gettype($rfc) != 'string' || $rfc == '') {
        return null;
    }

    $email_object = new stdClass;

    if (strpos($rfc, '>')) {
        preg_match('/^' . EMAIL_NAME . '<' . MAILBOX . '@(' . HOST . ')' . '\s*>\s*$/i', $rfc, $m);
        if (!$m) {
            return null;
        }
        $email_object->name = trim($m[1]);
    } else {
        preg_match('/^' . MAILBOX . '@(' . HOST . ')' . '\s*$/i', $rfc, $m);
        if (!$m) {
            return null;
        }
        array_unshift($m, null);
        $email_object->name = '';
    }

    $email_object->mailbox = strtolower($m[2]);
    $email_object->host    = strtolower($m[3]);
    $email_object->email   = $email_object->mailbox . '@' . $email_object->host;
    $email_object->domain  = strtolower($m[5]);

    return $email_object;
}
