GhostCatcher — sanal makine (VM) lab
====================================

Amaç: İki (veya daha fazla) VM — kurban (Debian/Ubuntu) + saldırgan (Kali) —
üzerinde docker/lab ile aynı senaryolar.

Dosya yerleşimi
---------------
vmlab/
  lab.env.example     →  lab.env olarak kopyalayın, IP’leri doldurun
  attackctl            →  victim kurulumu /usr/local/bin/’e koyar
  victim/
    install-victim.sh
    ghostcatcher-lab.config.yaml
    reset-lab.sh
    bench-all-scenarios.sh
  attacker/
    install-kali-attacker.sh
    run-all-remote-tests.sh
  www/                  →  (isteğe bağlı) depo dışı kopya web kökü

Kurban VM (önce)
----------------
1) Debian 12 veya Ubuntu 22.04+ ağ: saldırganla aynı host-only / LAN.
2) Bu repoyu kurbana kopyalayın (veya git clone).
3) cp vmlab/lab.env.example vmlab/lab.env
4) vmlab/lab.env içine VICTIM_IP, ATTACKER_IP yazın; SIEM varsa SIEM_LOKI_URL.
5) sudo bash vmlab/victim/install-victim.sh
6) attackctl check && attackctl baseline

Şüpheli davranış (kurban, yerel)
---------------------------------
- Ayrı sh (tavsiye, attackctl yok):
    cd /opt/lab/scenarios && sudo sh ./web-shell.sh
    GCLAB_RUN_SCAN=1 sudo sh ./web-shell.sh   # veya: sudo sh ./web-shell.sh scan
- attackctl:  attackctl apply web-shell && attackctl scan
- Tümü (uzun!):  sudo /opt/lab/bench-all-scenarios.sh
Senaryo betikleri: docker/lab/scenarios/ ile aynı; ayrıntı docker/lab/scenarios/README.txt

Kali VM (sonra)
---------------
1) Aynı repodan sadece vmlab/ yeter; lab.env aynı (VICTIM_IP dolu).
2) bash vmlab/attacker/install-kali-attacker.sh
3) Ekrandaki public key’i kurbana ekleyin (victim’te: KALI_SSH_PUB_KEY_LINE
   ile tekrar install veya /root/.ssh/authorized_keys).
4) bash vmlab/attacker/run-all-remote-tests.sh

Notlar
------
- eBPF / YARA bu kurulumda derleme etiketleri yok; varsayılan go build.
- SIEM (Loki/syslog) yoksa sink’ler kapalı; yalnızca stdout + isteğe filebeat.
- Üçüncü VM’de Loki açık ise lab.env: SIEM_LOKI_URL=http://<loki_ip>:3100
  ve victim install’i SIEM değişkenleriyle tekrar veya /etc/ghostcatcher/ el ile.
