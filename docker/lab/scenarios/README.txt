Her saldırı kategorisi için ayrı .sh (lib-env.sh hariç).

Doğrudan (konteyner veya VM kurban, root):
  cd /opt/lab/scenarios
  sudo sh ./web-shell.sh

Aynı komut, ardından tarama (ghostcatcher /usr/local’deyse):
  GCLAB_RUN_SCAN=1 sudo sh ./web-shell.sh
  veya
  sudo sh ./web-shell.sh scan

Yapılandırma (isteğe bağlı ortam değişkenleri):
  GCLAB_BIN=/usr/local/bin/ghostcatcher
  GCLAB_CFG=/etc/ghostcatcher/lab.config.yaml
  LAB_ROOT=/opt/lab   (scenarios’in üst dizini; lib-env türetir)

attackctl hâlâ desteklenir:  attackctl apply web-shell
