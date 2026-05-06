<?php
// NETWORK_WEB_WORKER_EGRESS: uzun süre dış ağa TCP
@ini_set('default_socket_timeout', 120);
$ctx = stream_context_create(['http' => ['timeout' => 120]]);
@file_get_contents('http://1.1.1.1:80', false, $ctx);
