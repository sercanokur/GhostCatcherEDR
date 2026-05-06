<?php
/*
 * Plugin Name: Hello Dolly
 */
function hello_dolly_get_lyric() {
    return "Hello, Dolly";
}
add_action('admin_notices', 'hello_dolly_get_lyric');
