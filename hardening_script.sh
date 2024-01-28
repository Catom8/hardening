#! /bin/bash

# Verificar si es root

if ["$(id -u)" !="0"]; then
echo "Este script debe ser ejecutado como root" 1>&2
exit 1

fi

# Actualización del sistema 
echo "Actualizando sistema"
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y


# Configuracion de plitica de contraseñas 
echo "Configuración de contraseñas segura" 

#Establecer longitud minuma de la contraseña y los requisitos

sudo sed -i 's/^password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

#Asgurarse que los cambios han sido aplicados
echo "Politica de contraseñas aplicada"

# Deshabilitar servicios innecesarios
echo "Deshabilitando servicios innecesarios..."

# Ejemplo:  Deshabilitar el servicio de impresión CUPS
sudo systemctl disable cups

# Deshabilitar el servidor de correo postfix
sudo systemctl disable postfix

echo "Servicios innecesarios deshabilitados."

# Configurar el firewall básico con ufw
echo "Configurando el firewall básico..."

# Habilitar ufw
sudo ufw enable

# Denegar todas las conexiones entrantes por defecto
sudo ufw default deny incoming

# Permitir todas las conexiones salientes por defecto
sudo ufw default allow outgoing

# Ejemplo: Permitir SSH (ajusta el puerto según tu configuración)
sudo ufw allow 22

echo "Firewall configurado."

# Instalar herramientas de seguridad recomendadas
echo "Instalando herramientas de seguridad adicionales..."
sudo apt-get install libpam-tmpdir apt-listbugs apt-listchanges needrestart debsums apt-show-versions -y

# Configurar contraseña en GRUB
echo "Configurando contraseña en GRUB..."
sudo grub-mkpasswd-pbkdf2 | tee /tmp/grubpassword.txt
echo "GRUB_PASSWORD=$(cat /tmp/grubpassword.txt | grep PBKDF2 | awk '{print $NF}')" | sudo tee -a /etc/grub.d/40_custom
sudo update-grub

# Configuraciones adicionales en /etc/login.defs
echo "Configurando /etc/login.defs..."
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10' /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs
sudo sed -i '/^UMASK/ c\UMASK           027' /etc/login.defs

# Deshabilitar protocolos de red no necesarios
echo "Deshabilitando protocolos de red no necesarios..."
echo "install dccp /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf
echo "install sctp /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf
echo "install rds /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf
echo "install tipc /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf

# Instalar y configurar auditd
echo "Instalando y configurando auditd..."
sudo apt-get install auditd -y
echo "-w /var/log/ -k log_files" | sudo tee -a /etc/audit/audit.rules
sudo systemctl restart auditd

# Deshabilitar core dumps
echo "Deshabilitando core dumps..."
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
echo "* soft core 0" | sudo tee -a /etc/security/limits.conf

# Configurar rondas de hashing de contraseñas
echo "Configurando rondas de hashing para contraseñas..."
sudo sed -i '/^SHA_CRYPT_MIN_ROUNDS/ c\SHA_CRYPT_MIN_ROUNDS 5000' /etc/login.defs
sudo sed -i '/^SHA_CRYPT_MAX_ROUNDS/ c\SHA_CRYPT_MAX_ROUNDS 10000' /etc/login.defs

# Deshabilitar almacenamiento USB y Firewire
echo "Deshabilitando almacenamiento USB y Firewire..."
echo "install usb-storage /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf
echo "install firewire-core /bin/true" | sudo tee -a /etc/modprobe.d/blacklist.conf

# Revisar y limpiar paquetes antiguos
echo "Limpiando paquetes antiguos..."
sudo apt-get autoremove --purge -y

# Instalar y configurar herramientas de seguridad para Apache
if [ -x "$(command -v apache2)" ]; then
    echo "Instalando mod_evasive y modsecurity para Apache..."
    sudo apt-get install libapache2-mod-evasive libapache2-modsecurity -y
fi

# Agregar banners legales
echo "Agregando banners legales a /etc/issue y /etc/issue.net..."
echo "Authorized use only. All activity may be monitored and reported." | sudo tee /etc/issue
sudo cp /etc/issue /etc/issue.net

# Habilitar contabilidad de procesos y sysstat
echo "Habilitando contabilidad de procesos y sysstat..."
sudo apt-get install acct sysstat -y
sudo systemctl enable acct
sudo systemctl start acct
sudo sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
sudo service sysstat restart

# Instalar herramientas de integridad de archivos
echo "Instalando herramientas de integridad de archivos..."
sudo apt-get install rkhunter chkrootkit -y

# Restringir acceso a compiladores
echo "Restringiendo acceso a compiladores..."
sudo chmod 700 /usr/bin/gcc /usr/bin/g++ /usr/bin/make

# Instalación de herramientas para actualizaciones automáticas
echo "Instalando unattended-upgrades para actualizaciones automáticas..."
sudo apt-get install unattended-upgrades -y


# Instalar y configurar USBGuard
echo "Instalando y configurando USBGuard..."
sudo apt-get install usbguard -y

# Inicializar la configuración de USBGuard con dispositivos actuales permitidos
sudo usbguard generate-policy > /etc/usbguard/rules.conf

# Habilitar y arrancar el servicio de USBGuard
sudo systemctl enable usbguard
sudo systemctl start usbguard

echo "USBGuard instalado y configurado."

#Hardening Completado
echo "Hardening adicional completado."
