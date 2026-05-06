# Tespit ↔ Docker lab matrisi

GhostCatcher’ın ürettiği **rule_id** değerleri ile `docker/lab/scenarios` betiklerinin eşlemesi.  
Lab ağı: `docker compose up --build` → servis **lab** (`attackctl` komutları).

**Durum anahtarı**

| Durum | Anlamı |
|-------|--------|
| **Evet** | Hazır senaryo: `attackctl apply <ad>` |
| **Kısmen** | Lab içinde mümkün; ek adım veya host/kernel bağımlılığı |
| **Hayır** | Varsayılan lab imajı / derleme ile gerçekçi deneme yok |

---

## Tam matris (rule_id)

**Her tespit için ayrı betik** — `docker/lab/scenarios/<ad>.sh` doğrudan çalıştırılabilir:  
`cd /opt/lab/scenarios && sudo sh ./<ad>.sh` — tarama eklemek için: `GCLAB_RUN_SCAN=1` veya `sudo sh ./<ad>.sh scan`. Ayrıntı: `docker/lab/scenarios/README.txt`

| rule_id | Kısa açıklama | Lab |
|---------|---------------|-----|
| `WEB_SHELL_PATTERN` | Web shell / PHP taint vb. | **Evet** → `web-shell` |
| `WEB_WORKER_RECON_CHILD` | Web işçi altında recon argv | **Evet** → `web-recon` |
| `CRON_HIGH_RISK` | Yüksek risk cron içeriği | **Evet** → `cron` |
| `LD_SO_PRELOAD_FILE` | `/etc/ld.so.preload` | **Evet** → `ld-preload-file` |
| `PROC_LD_PRELOAD_ENV` | Süreç ortamında `LD_PRELOAD` | **Evet** → `ld-preload-env` |
| `SSH_AUTHKEY_NEW` | Yeni authorized_keys parmak izi | **Evet** → `ssh-key` |
| `SSH_AUTHKEY_INVALID_LINE` | Geçersiz anahtar satırı | **Evet** → `ssh-auth-invalid` |
| `SUDOERS_PERSISTENCE` | sudoers kayması | **Evet** → `sudoers` |
| `SYSTEMD_PERSISTENCE` | Unit/timer şüpheli `Exec*` vb. | **Evet** → `systemd` |
| `PAM_PERSISTENCE` | PAM yapılandırması / şüpheli modül | **Evet** → `pam` |
| `SHELL_RC_PERSISTENCE` | Shell rc dosyaları | **Evet** → `shellrc` |
| `KERNEL_MODLOAD_PATH_CHANGED` | modules-load.d / modprobe.d değişimi | **Evet** → `kmod` |
| `KERNEL_MODULE_NEW` | Yüklü çekirdek modülü kümesi değişti | **Kısmen** — konteynerde genelde sınırlı modül; `modprobe` denemesi host’a bağlı |
| `LD_SO_CONF_CHANGED` | `ld.so.conf.d` kayması | **Evet** → `ldconf` |
| `SSHD_CONFIG_ANOMALY` | sshd yapılandırması risk sinyali | **Evet** → `sshd-config` |
| `USER_ACCOUNT_ANOMALY` | passwd/shadow anomalisi | **Evet** → `user-account` |
| `BINARY_INTEGRITY_MD5_MISMATCH` | dpkg/rpm bütünlük (izlenen yol) | **Evet** → `integrity-dpkg` |
| `SUID_INVENTORY_DELTA` | SUID/SGID envanter farkı | **Evet** → `suid` |
| `FILE_CAPABILITY_DELTA` | `file capability` xattr farkı | **Evet** → `capability` |
| `NETWORK_UNEXPECTED_LISTEN` | Beklenmeyen dinleme (RFC1918 dışı değil, loopback değil) | **Evet** → `network-listen` |
| `NETWORK_REVERSE_SHELL` | Kabuk benzeri süreç, özel ağ dışı giden TCP | **Evet** → `network-reverse` |
| `NETWORK_WEB_WORKER_EGRESS` | nginx/php-fpm vb. dış giden bağlantı | **Evet** → `network-egress` |
| `PROC_RWX_MEMORY_SEGMENT` | `/proc/*/maps` RWX | **Kısmen** — `lab.config.yaml` içinde `maps_scan_enabled: true` + uygun süreç |
| `PROC_DELETED_EXEC_SEGMENT` | maps: silinmiş yürütme | **Kısmen** — aynı (maps + tetikleyici süreç) |
| `PROC_WORLD_WRITABLE_MAPPING` | maps: world-writable | **Kısmen** — aynı |
| `PROC_UNEXPECTED_TRACER` | TracerPid şüphesi | **Kısmen** — aynı |
| `PROC_UNEXPECTED_LIBRARY` | Beklenmeyen .so | **Kısmen** — baseline kütüphane + maps |
| `PROC_CAP_ESCALATION` | CapEff şüphesi | **Kısmen** — maps + süreç |
| `PROC_RARE_ANCESTRY` | Baselined olmayan nadir parent/child | **Hayır** — otomatik senaryo yok; kontrollü `baseline` + el ile süreç ağacı gerekir |
| `YARA_DISK_MATCH` | YARA disk | **Hayır** — `-tags with_yara` + kural dosyası gerekir |
| `YARA_PROCESS_MATCH` | YARA bellek | **Hayır** — aynı |
| `AGENT_TAMPERED` | İkili bütünlük (selfguard) | **Kısmen** — ikiliyi değiştirip `selfguard` açık config; lab imajında varsayılan kapalı |

---

## Ek özellikler (ayrı rule_id değil)

| Özellik | Lab |
|---------|-----|
| **IOC** sinyal ağırlığı (hash/IP/domain listeleri) | **Kısmen** — `ioc_*_files` yollarına dosya mount + kural eşleşmesi |
| **Quarantine** kanıt kasası | **Kısmen** — `quarantine_dir` + yüksek güven olayı (ör. web shell) |
| **Sigma-lite** import | **Evet** — `sigma_lite_dir` mount + kural |
| **Korelasyon penceresi** | **Evet** — rule pack + ardışık senaryolar |

---

## Hızlı komut özeti

```bash
docker compose exec lab attackctl list
docker compose exec lab attackctl reset
docker compose exec lab attackctl baseline
docker compose exec lab attackctl apply <senaryo-adı>
docker compose exec lab attackctl scan
```

Senaryo adı, `docker/lab/scenarios/` altındaki `.sh` dosya adıdır (`web-shell`, `cron`, …).

---

## Not

- **eBPF** sensörü (`with_ebpf`) varsayılan lab ikilisinde yok; olay akışı auditd / proc fallback ile sınırlıdır.
- **KERNEL_MODULE_NEW** için anlamlı sonuç genelde modül yükleyebilen bir Linux host gerekir.
