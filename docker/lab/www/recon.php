<?php
header('Content-Type: text/plain; charset=utf-8');
// WEB_WORKER_RECON_CHILD: web işçi altında whoami
echo shell_exec('whoami 2>&1');
