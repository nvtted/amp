#!/bin/bash
#CubeCoders AMP Installer (C)2019-2022 CubeCoders Limited

function isPresent { command -v "$1" &> /dev/null && echo 1; }
function isFileOpen { lsof "$1" &> /dev/null && echo 1; }

echo "Please wait while GetAMP examines your system and network configuration..."

ARCH=$(uname -m)
AMP_SYS_USER=amp
AMP_ADS_PORT=8080
AMP_ADS_IP="0.0.0.0"
GETAMP_VERSION="2.8.0"
DNS_SERVER="8.8.8.8"

AMP_USER_EXISTS=$(grep -c :/home/$AMP_SYS_USER: /etc/passwd)
AMPINSTMGR_IS_INSTALLED="$(isPresent ampinstmgr)"
NFT_IS_PRESENT="$(isPresent nft)"
IPTABLES_IS_PRESENT="$(isPresent iptables)"
UFW_IS_PRESENT="$(isPresent ufw)"
FIREWALLCMD_IS_PRESENT="$(isPresent firewall-cmd)"
SS_IS_PRESENT="$(isPresent ss)"
CURL_IS_PRESENT="$(isPresent curl)"
DIG_IS_PRESENT="$(isPresent dig)"
USERADD_IS_PRESENT="$(isPresent useradd)"
TPUT_IS_PRESENT="$(isPresent tput)"
SELINUX_IS_INSTALLED="$(isPresent setsebool)"
DOCKER_IS_INSTALLED="$(isPresent docker)"
APT_IS_PRESENT="$(isPresent apt-get)"
YUM_IS_PRESENT="$(isPresent yum)"
PACMAN_IS_PRESENT="(isPresent pacman)"
JQ_IS_PRESENT="$(isPresent jq)"
IP_IS_PRESENT="$(isPresent ip)"
SNAP_IS_PRESENT="$(isPresent snap)"
STATUS_FILE=/opt/cubecoders/amp/shared/WebRoot/installState.json
JAVA_PACKAGE="temurin-8-jdk temurin-17-jdk temurin-18-jdk"

if [ ! "$USERADD_IS_PRESENT" ]; then
	echo "The useradd command isn't available in the current environment. It's missing from \$PATH"
	echo "Try running 'sudo -i' and trying again. Do not re-run the same command with 'sudo' in front."
	exit 130
fi

if [ ! "$TPUT_IS_PRESENT" ]; then
	echo "The tput command isn't available in the current environment. It's missing from \$PATH"
	echo "This usually means you're using an unsupported Linux distribution."
	exit 132
fi

LOG_FILE="$HOME/getamp-$(date +%Y%m%d-%H%M%S).log"
INSTALL_SUMMARY=~/ampsummary.log
date > "$LOG_FILE"

BoldText=$(tput bold 2> /dev/null)
NormalText=$(tput sgr0 2> /dev/null)
UnderlineText=$(tput smul 2> /dev/null)

if [ "$UFW_IS_PRESENT" ]; then
	UFWSTATUS=$(ufw status)

	if [ "$UFWSTATUS" == "inactive" ]; then
		echo "${BoldText}Warning: \'ufw\' is installed, but it is not the systems default firewall.${NormalText}"
		echo "AMP will revert to another firewall, but if you change this down the line you may"
		echo "need to manually add/update firewall rules."
		unset UFW_IS_PRESENT
	fi
fi

FIREWALL=none
if [ "$UFW_IS_PRESENT" ]; then FIREWALL=ufw;
elif [ "$FIREWALLCMD_IS_PRESENT" ]; then FIREWALL=firewalld;
elif [ "$IPTABLES_IS_PRESENT" ]; then FIREWALL=iptables; 
elif [ "$NFT_IS_PRESENT" ]; then FIREWALL=nft; fi;

if [ "$IP_IS_PRESENT" ]; then
	read -r _{,} GATEWAY_IP _ _ _ INTERNAL_IP _ < <(ip r g 1.0.0.0)
else
	INTERNAL_IP=$(hostname -I | cut -f 1 -d ' ')
fi

if [ "$SS_IS_PRESENT" ]; then
	NS_COMMAND=ss
else
	NS_COMMAND=netstat
fi

if [ "$APT_IS_PRESENT" ]; then
	export DEBIAN_FRONTEND=noninteractive
	PM_COMMAND=apt-get
	PM_INSTALL=(install -y)
	CERTBOT_PACKAGE=python3-certbot-nginx
	LIB32_PACKAGES="lib32stdc++6 lib32z1 libncurses5:i386 libbz2-1.0:i386 libtinfo5:i386 libcurl3-gnutls:i386 libsdl2-2.0-0:i386"
	PREREQ_PACKAGES="dirmngr software-properties-common apt-transport-https gpg-agent dnsutils jq git unzip wget gpg qrencode"
	PM_LOCK_FILE="/var/lib/dpkg/lock"
	INSTALL_IN_PROGRESS=$(isFileOpen $PM_LOCK_FILE)

	if [ "$FIREWALL" == "iptables" ] && [ ! -d /etc/iptables ]; then
		PREREQ_PACKAGES="$PREREQ_PACKAGES iptables-persistent"
	fi

	if [ "$VERSION_ID" == "8" ]; then
		CERTBOT_PACKAGE=
	fi
elif [ "$YUM_IS_PRESENT" ]; then
	PM_COMMAND=yum
	PM_INSTALL=(-y install)
	LIB32_PACKAGES="glibc.i686 libstdc++.i686 ncurses-libs.i686"
	PREREQ_PACKAGES="wget tmux socat unzip git bind-utils tar jq qrencode"
	CERTBOT_PACKAGE=python3-certbot-nginx
	PM_LOCK_FILE="/var/run/yum.pid"
	INSTALL_IN_PROGRESS=$(isFileOpen $PM_LOCK_FILE)
elif [ "$PACMAN_IS_PRESENT" ]; then
	PM_COMMAND=pacman
	PM_INSTALL=(-S --noconfirm)
	LIB32_PACKAGES="lib32-glibc lib32-gcc-libs"
	PREREQ_PACKAGES="wget tmux socat unzip git dnsutils tar jq qrencode"
	CERTBOT_PACKAGE=certbot-nginx
	JAVA_PACKAGE="jre8-openjdk-headless jre-openjdk-headless"

	if [ "$ARCH" != "x86_64" ]; then
		echo "AMP only supports aarch64 on Debian and Red Hat/CentOS based distros at this time."
		exit
	fi
else
	echo "This system doesn't appear to be supported. No supported package manager (apt/yum/pacman) was found."
	echo "Automated installation is only availble for Debian, Red-Hat and Arch based distrubitions, including Ubuntu and CentOS."
	echo "$NAME is not a supported distribution at this time."
	exit
fi

if [ "$INSTALL_IN_PROGRESS" ]; then
	echo "Your package manager is currently performing another installation."
	echo "Please wait for that to finish before installing AMP."
	echo
	echo "Info: A lock is open on $PM_LOCK_FILE"
	exit 131
fi

if [ "$CURL_IS_PRESENT" ]; then
	EXTERNAL_IP=$(curl https://ipecho.net/plain 2> /dev/null)
else
	EXTERNAL_IP=$(wget -qO- https://ipecho.net/plain 2> /dev/null)
fi

export EXTERNAL_IP
NETWORK_TYPE=$([[ "$INTERNAL_IP" == "$EXTERNAL_IP" ]] && echo "Direct" || echo "NAT")
#NETWORK_TYPE=$([ "$(traceroute -m 4 google.com | grep -ic " 100.64." || echo 0)" -gt 0 ] && echo "CGNAT" || echo "$NETWORK_TYPE")

syspass=
ampuser=
amppass=

if [ ! -f /etc/os-release ]; then
	echo "No OS info available. Missing /etc/os-release"
	exit 20
fi

if ! [[ "$LANG" =~ ^.+\.(UTF-8|utf8)$ ]]; then
	echo "System locale is not a UTF-8 compatible locale, it is currently $LANG"
	echo "Please update your system locale to a UTF-8 one and reboot before running this script."
	if [ "$APT_IS_PRESENT" ]; then
		echo "You can do this by running 'dpkg-reconfigure locales && locale-gen' as root and making sure a UTF-8 locale for your region/language is selected."
		echo "On some systems it may be 'update-locale LANG=en_GB.utf8' instead."
	else
		echo "Please consult your distributions documentation for how to configure your system for a UTF-8 compatible locale."
	fi
	echo "It may be necessary to log out and log in again for locale changes to take effect."
	exit 30
fi

export TERM=xterm

# shellcheck disable=1091
source /etc/os-release

if [ "$VERSION_ID" == "16.04" ]; then
	echo "Warning: Ubuntu 16.04 is no longer supported by AMP. Please upgrade to 18.04 or newer."
	exit
fi

if [[ $EUID -ne 0 ]]; then
	echo "You need root access to run this script! Try running 'sudo su' as a separate command first."
	echo "${BoldText}Do not just run the same command again with 'sudo' in front!${NormalText}"
	exit 40
fi

if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
	echo "AMP is only supported on x86_64 and aarch64 systems. You are running $ARCH"
	exit 64
fi

if [ "$ARCH" == "aarch64" ]; then
	reposuffix=$ARCH/
fi

if [ "$(mount | grep -icE '^tmpfs.+?\/tmp.+?noexec.+$')" -gt 0 ]; then
	echo "Your /tmp filesystem has the 'noexec' flag set. Please edit your /etc/fstab file to not have the noexec flag on /tmp"
	echo "You will need to reboot your system after making this change"
	exit 120
fi

if [ -f /var/run/scw-metadata.cache ]; then
	CLOUD_PROVIDER=Scaleway
	EXT_HOSTNAME=$(grep -oP '^ID=\K.+$' /var/run/scw-metadata.cache).pub.cloud.scaleway.com
else
	if [ "$(grep -ic ovh /etc/resolv.conf)" -gt 0 ]; then CLOUD_PROVIDER=OVH;
	elif [ "$(grep -ic hetzner /var/run/cloud-init/instance-data.json &> /dev/null || echo 0)" -gt 0 ]; then CLOUD_PROVIDER="Hetzner";
	elif [ "$(grep -ic linode /etc/resolv.conf)" -gt 0 ]; then CLOUD_PROVIDER="Linode";
	elif [ "$(grep -ic oracle /etc/resolv.conf)" -gt 0 ]; then CLOUD_PROVIDER="Oracle";
	elif [ "$(grep -ic ec2 /etc/resolv.conf)" -gt 0 ]; then CLOUD_PROVIDER="Amazon";
	elif [ -f /var/run/cloud-init/cloud-id-azure ]; then CLOUD_PROVIDER="Azure";
	elif [ -f /etc/cloud/digitalocean.info ]; then CLOUD_PROVIDER="DigitalOcean"; fi

	if [ "$DIG_IS_PRESENT" ]; then
		FQDN=$(hostname -f)
		if [ "$FQDN" != "localhost" ]; then
			fqdnip=$(dig "$DNS_SERVER" +short "$FQDN" | tail -n 1)

			if [ "$fqdnip" == "$EXTERNAL_IP" ]; then
				EXT_HOSTNAME=$FQDN
			fi
		fi

		if [ -z "$EXT_HOSTNAME" ]; then
			digout=$(dig "$DNS_SERVER" +short -x "$EXTERNAL_IP" | tail -n 1)
			if [ -n "$digout" ]; then
				reverse="${digout::-1}"
				verify=$(dig "$DNS_SERVER" +short "$digout" | tail -n 1)

				if [ "$verify" == "$EXTERNAL_IP" ]; then
					EXT_HOSTNAME=$reverse
				fi
			fi
		fi
	elif [[ "$FQDN" =~ ^.+?(\..+)+$ ]]; then
		EXT_HOSTNAME=$FQDN
	fi
fi

export EXT_HOSTNAME

function showSystemInfo {
	echo "Distribution        : $ID $VERSION_ID"
	echo "Platform            : $ARCH"
	echo "Internal IP address : $INTERNAL_IP"
	echo "External IP address : $EXTERNAL_IP"
	echo "Network type        : $NETWORK_TYPE"
	if [ "$NETWORK_TYPE" == "NAT" ] && [ -n "$GATEWAY_IP" ]; then echo "Gateway IP address  : $GATEWAY_IP"; fi
	echo "Detected Firewall   : $FIREWALL"
	if [ -n "$EXT_HOSTNAME" ]; then echo "External Host name  : $EXT_HOSTNAME"; fi
	if [ -n "$CLOUD_PROVIDER" ]; then echo "Service Provider    : $CLOUD_PROVIDER"; fi
	echo "System Locale       : $LANG"
	echo "Package Manager	    : $PM_COMMAND"
}

function configureDarkMagicNew {
	if [ "$ARCH" != "aarch64" ]; then
		echo "CPx2 is only applicable to aarch64 systems."
	fi

	if [ "$ID" != "ubuntu" ]; then
		echo "CPx2 is only supported on Ubuntu at this time."
	fi

	oldpwd=$(pwd)
	
	echo "Installing CPx2..."
	echo " - Configuring package manager and installing dependencies..."
	{
	dpkg --add-architecture armhf
	$PM_COMMAND update
	$PM_COMMAND "${PM_INSTALL[@]}" git build-essential cmake libsdl2-dev libsdl2-2.0-0 gcc-arm-linux-gnueabihf libc6:armhf libncurses5:armhf libstdc++6:armhf
	} &>> "$LOG_FILE"
	cd ~ || return
	echo " - Fetching sources..."
	{
	git clone --depth=1 https://github.com/ptitSeb/box86
	git clone --depth=1 https://github.com/ptitSeb/box64
	} &>> "$LOG_FILE"
	echo " - Compiling 32-bit x86 support... (This may take a while)"
	{
		mkdir ~/box86/build;
		cd ~/box86/build || return;
		cmake .. -DRPI4ARM64=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo;
		make "-j$(nproc)";
		make install;
	} &>> "$LOG_FILE"
	echo " - Compiling x86_64 support... (This may take a while)"
	{
		mkdir ~/box64/build;
		cd ~/box64/build || return;
		cmake .. -DRPI4ARM64=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo;
		make "-j$(nproc)";
		make install;
	} &>> "$LOG_FILE"
	echo " - Restarting system services..."
	systemctl restart systemd-binfmt &>> "$LOG_FILE"
	rm -r ~/box86 ~/box64
	cd "$oldpwd" || return
	echo " - Done!"
}

function configureDarkMagic {
	if [ "$ARCH" != "aarch64" ]; then
		echo "CPx is only applicable to aarch64 systems."
	fi
	if [ "$ID" != "ubuntu" ]; then
		echo "CPx is only supported on Ubuntu at this time."
	fi

	if [ "$(grep -icE '^deb \[arch=amd64' /etc/apt/sources.list)" -gt 0 ]; then
		echo "CPx appears to be already configured on this system. Skipping..."
		return
	fi

	echo "Configurating package manager for CPx. This may take some time..."

	echo " - Updating package sources list..."
	sed -i 's/deb http/deb [arch=arm64,armhf] http/' /etc/apt/sources.list
	sed -i 's/deb \[/deb [arch=arm64,armhf /' /etc/apt/sources.list
	cat <<EOF >> /etc/apt/sources.list
deb [arch=amd64,i386] http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} main
deb [arch=amd64,i386] http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} universe
deb [arch=amd64,i386] http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} multiverse
deb [arch=amd64,i386] http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates main
deb [arch=amd64,i386] http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates universe
deb [arch=amd64,i386] http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates multiverse
EOF

	echo " - Adding i386 and amd64 architectures..."
	{
	dpkg --add-architecture i386;
	dpkg --add-architecture amd64;
	} &>> "$LOG_FILE"

	echo " - Updating package list..."
	{
	apt-get update;
	apt-get upgrade;
	} &>> "$LOG_FILE"

	echo " - Installing support packages..."
	{
	apt-get install -y binfmt-support qemu-user qemu-user-binfmt;
	apt-get install -y zlib1g:amd64 libssl1.1:amd64 libstdc++6:amd64 libc6:amd64 lib32stdc++6:amd64 lib32z1:amd64 libncurses5:i386 libbz2-1.0:i386 libtinfo5:i386 libcurl3-gnutls:i386 libsdl2-2.0-0:i386
	} &>> "$LOG_FILE"
	echo " - Done!"
}

function upgradeCPX {
	if [ "$(grep -icE '^deb \[arch=amd64' /etc/apt/sources.list)" -gt 0 ]; then
		apt-get remove -y qemu-user qemu-user-binfmt zlib1g:amd64 libssl1.1:amd64 libstdc++6:amd64 libc6:amd64 lib32stdc++6:amd64 lib32z1:amd64 libncurses5:i386 libbz2-1.0:i386 libtinfo5:i386 libcurl3-gnutls:i386 libsdl2-2.0-0:i386;
		dpkg --remove-architecture i386;
		dpkg --remove-architecture amd64;
	fi
	configureDarkMagicNew
}

function showWelcome {
	if [ -z "$USE_ANSWERS" ]; then
		clear
		echo
		echo "GetAMP v$GETAMP_VERSION"
		echo "AMP QuickStart installation script for Debian, Red-Hat and Arch based GNU/Linux distributions"
		echo "This installer will perform the following:"
		echo 
		echo " * Install any pending system updates"
		echo " * Install any prerequisites and dependencies via your systems package manager"
		echo " * Add the CubeCoders repository to your system to keep AMP updated"
		echo " * Install AMP and create a default management instance on port $AMP_ADS_PORT"
		echo " * Create any firewalls necessary to allow you to connect to AMP"
		echo " * Configure the default AMP instance to start on boot"
		echo 
		echo "Press CTRL+C to cancel installation."
		echo
		echo "It is safe to cancel this installation at any point. You can run the install"
		echo "script again, and the script will skip any steps it has already completed."
		echo
	fi
	showSystemInfo
	echo
}

function promptForSystemUser {
	if [ -n "$USE_ANSWERS" ]; then
		syspass=$ANSWER_SYSPASSWORD
		return
	fi

	echo "Enter a password to use with the $AMP_SYS_USER system user."
	echo "Leave blank to randomly generate a strong password."
	echo
	read -rsp "System Password [autogenerate]: " syspass
	echo

	if [ -z "$syspass" ]; then
		syspass=$(cat /proc/sys/kernel/random/uuid)
	else
		read -rsp "Confirm System Password:" syspassconfirm
		echo
		echo

		if [ "$syspass" != "$syspassconfirm" ]; then
			echo "Confirmation password does not match. Aborting."
			exit 50
		fi

		syspass=$(printf %q "$syspass")
	fi	
}

function promptForAMPUser {
	if [ -n "$USE_ANSWERS" ]; then
		ampuser=$ANSWER_AMPUSER
		amppass=$ANSWER_AMPPASS
		return
	fi

	echo "Enter new login details for use with AMP."
	echo "${BoldText}No special characters${NormalText} in either the username or password."
	echo "${BoldText}Letters and numbers only.${NormalText}"
	echo "You can change your details after running through the setup."
	echo
	echo "${BoldText}The password must not be the same as the system password!${NormalText}"
	read -rp "Username [admin]: " ampuser
	ampuser=${ampuser:-admin}
	read -rsp "Password: " amppass
	if [ -z "$amppass" ]; then
		echo "You must provide a password for the AMP login user."
		exit 60
	fi
	echo
	read -rsp "Confirm Password:" amppassconfirm
	echo
	echo

	if [ "$syspass" == "$amppass" ]; then
		echo "The system and AMP passwords cannot be the same. Aborting."
		exit 70
	fi

	if [ "$amppass" != "$amppassconfirm" ]; then
		echo "Confirmation password does not match. Aborting."
		exit 80
	fi

	printf -v amppass "%q" "${amppass}"
	printf -v ampuser "%q" "${ampuser}"
}

function promptForDeps {
	if [ -n "$USE_ANSWERS" ]; then
		installJava=$ANSWER_INSTALLJAVA
		installsrcdsLibs=$ANSWER_INSTALLSRCDSLIBS
		installDocker=$ANSWER_INSTALLDOCKER
		return
	fi

	echo "Will you be running Minecraft servers on this installation?"
	echo "If selected, this installs the required versions of Java."
	read -n1 -rp "[Y/n] " installJava
	installJava=${installJava:-y}
	echo
	echo

	if [ "$ARCH" == "x86_64" ]; then
		echo "Will you be running applications that rely on SteamCMD? (Rust, Ark, CSGO, TF2, etc) on this installation?"
		echo "If selected, this will install the required additional 32-bit libraries."
		read -n1 -rp "[Y/n] " installsrcdsLibs
		installsrcdsLibs=${installsrcdsLibs:-y}
		echo
		echo

		echo "Would you like to isolate your AMP instances by running them inside Docker containers?"
		echo "This provides an additional layer of protection at the expense of a minor performance impact."
		echo "It is strongly recommended if you are going to allow untrusted users access to AMP"
		echo "but if it's just yourself or trusted users accessing it then it may not be necessary."
		read -n1 -rp "[y/N] " installDocker
		installDocker=${installDocker:-n}
		echo
		echo
	fi

	if [ "$ARCH" == "aarch64" ] && [ "$ID" == "ubuntu" ]; then
		echo "Would you like to configure this system for cross-platform execution (CPx2)?"
		echo "This allows AMP to run a limited number of x86_64 applications on aarch64 systems."
		echo "Be aware that this makes significant changes to your systems package manager"
		echo "configuration but this should not affect normal operation of the system."
		echo
		echo "${BoldText}We recommend against using this functionality on systems that run"
		echo "applications other than AMP at this time.${NormalText}"
		read -n1 -rp "[y/N] " installDarkMagic
		installDarkMagic=${installDarkMagic:-n}
		echo
		echo
	fi
}

function promptForHTTPS {
	if [ -n "$USE_ANSWERS" ]; then
		setupnginx=Y
		nginxdomain=$EXT_HOSTNAME
		nginxemail=$ANSWER_EMAIL
		return
	fi

	echo "Would you like AMP to be configured for use with HTTPS?"
	echo 
	echo "This will install nginx on your system and requires that you do not use any"
	echo "other web servers such as Apache on this system."
	echo
	echo "This will create firewall rules to open ports 80 (HTTP) and 443 (HTTPS)"
	if [ "$SELINUX_IS_INSTALLED" ]; then
		echo "and also selinux rules to allow nginx to act as a reverse proxy."
	fi
	echo "You also must own a domain name that resolves to ${BoldText}$EXTERNAL_IP${NormalText} (Your external IP)"
	if [ -n "$EXT_HOSTNAME" ]; then
		echo
		echo "GetAMP has automatically detected an externally resolvable domain of $EXT_HOSTNAME"
		echo "You can either use this or you can supply your own subdomain at the next step."
	fi
	echo
	echo "${BoldText}Do not choose this option if you do not already own a domain.${NormalText}"
	echo 
	echo "Using this facility requires that you read and accept the LetsEncrypt terms at"
	echo "${UnderlineText}https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf${NormalText}"
	echo
	echo "Enable HTTPS?"
	read -n1 -rp "[y/N] " setupnginx
	echo
	echo

	if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
		apache_is_present=$(isPresent apache2)
		AMP_ADS_IP="127.0.0.1"
		if [ "$apache_is_present" ]; then
			echo "Apache2 is installed, which will conflict with nginx as required for AMPs reverse proxy - Aborting."
			echo "Either remove Apache2 and try again, or re-run this script and select 'No' when asked if you wish to use HTTPS"
			exit 90
		fi

		echo "Please specify which domain you wish to use."
		echo "${BoldText}You should use a subdomain that is only going to be used for AMP.${NormalText}"
		echo "E.g. ${BoldText}amp.mydomain.com${NormalText}"

		if [ -n "$EXT_HOSTNAME" ]; then
			read -rp "Domain [$EXT_HOSTNAME]: " nginxdomain
			nginxdomain=${nginxdomain:-$EXT_HOSTNAME}
		else
			read -rp "Domain: " nginxdomain
		fi

		if [ -z "$nginxdomain" ]; then
			echo "Using HTTPS requires that you specify a domain. Do not select this option if you don't have one."
			exit 91
		fi

		echo "Please enter your email address (Optional)"
		echo "LetsEncrypt will send important certificate notifications here."
		read -rp "Email: " nginxemail

		if [ "$NETWORK_TYPE" == "NAT" ]; then
			echo "GetAMP has detected that you are currently behind a NAT."
			echo "Please forward ports 80 and 443 TCP to $INTERNAL_IP if you have not already done so."
			read -n 1 -s -r -p "Press any key to continue once you have done this."
		fi
	fi
}

function createUser {
	echo "Creating system user..."
	
	if ! useradd -G tty -d /home/"$AMP_SYS_USER" -m "$AMP_SYS_USER" -s /bin/bash &>> "$LOG_FILE"; then
		echo "Failed to add system user. Aborting..."
		promptLogUpload
		exit 11
	fi
	echo "$AMP_SYS_USER:$syspass" | chpasswd
	{
		echo "export TERM=xterm" 
		echo 'export PS1=" \[\e[30;41m\]\[\e[m\]\[\e[37;41m\] CubeCoders AMP \[\e[m\]\[\e[31;44m\]\[\e[m\]\[\e[44m\] 💻\u\[\e[m\]\[\e[44m\]@\[\e[m\]\[\e[44m\]\h \[\e[m\]\[\e[34;42m\]\[\e[m\]\[\e[30;42m\] 📁\w \[\e[m\]\[\e[32;40m\]\[\e[m\] "'
		echo "alias sudo=\"echo You cannot use sudo while logged in as the \\\'amp\\\' user, you need to be logged in as an administrator/root user do to that.\;\#\""
		echo "alias htop=\"htop -u $AMP_SYS_USER\""
	} >> /home/$AMP_SYS_USER/.profile
	mkdir -p "/home/$AMP_SYS_USER/.config/htop/"
	cat <<EOF > /home/$AMP_SYS_USER/.config/htop/htoprc
# Beware! This file is rewritten by htop when settings are changed in the interface.
# The parser is also very primitive, and not human-friendly.
fields=0 48 111 38 46 47 49 1
sort_key=46
sort_direction=1
hide_threads=1
hide_kernel_threads=1
hide_userland_threads=1
shadow_other_users=1
show_thread_names=0
show_program_path=1
highlight_base_name=1
highlight_megabytes=1
highlight_threads=1
tree_view=1
header_margin=1
detailed_cpu_time=0
cpu_count_from_zero=1
update_process_names=0
account_guest_in_cpu_meter=0
color_scheme=4
delay=15
left_meters=LeftCPUs2 Memory Swap Clock
left_meter_modes=1 1 1
right_meters=RightCPUs2 Tasks LoadAverage Uptime
right_meter_modes=1 2 2 2
EOF
	chown $AMP_SYS_USER:$AMP_SYS_USER "/home/$AMP_SYS_USER/.profile"
	chown -R $AMP_SYS_USER:$AMP_SYS_USER "/home/$AMP_SYS_USER/.config"
}

function updateSystem {
	echo "Updating System..."
	if [ "$APT_IS_PRESENT" ]; then
		apt-get update &>> "$LOG_FILE"
		apt-get upgrade -y &>> "$LOG_FILE"
	elif [ "$YUM_IS_PRESENT" ]; then
		yum update -y &>> "$LOG_FILE"
	elif [ "$PACMAN_IS_PRESENT" ]; then
		sed -i "/\[multilib\]/,/Include/"'s/^#//' /etc/pacman.conf
		pacman -Syu --noconfirm &>> "$LOG_FILE"
	fi
}

function installJava {
	if [ "$APT_IS_PRESENT" ]; then
	{
		echo Adding AdoptOpenJDK APT repository...
		wget -qO- https://packages.adoptium.net/artifactory/api/gpg/key/public > /usr/share/keyrings/adoptium.asc
		echo "deb [signed-by=/usr/share/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb $VERSION_CODENAME main" | sudo tee /etc/apt/sources.list.d/adoptium.list
		apt-get update;
	} &>> "$LOG_FILE"
	elif [ "$YUM_IS_PRESENT" ]; then
		echo Adding AdoptOpenJDK RPM repository...
		
		$PM_COMMAND install -y epel-release &>> "$LOG_FILE"
		yum repolist &>> "$LOG_FILE"

		cat <<EOF > /etc/yum.repos.d/adoptium.repo
[Adoptium]
name=Adoptium
baseurl=https://packages.adoptium.net/artifactory/rpm/$ID/$VERSION_ID/$(uname -m)
enabled=1
gpgcheck=1
gpgkey=https://packages.adoptium.net/artifactory/api/gpg/key/public
EOF
		yum check-update &>> "$LOG_FILE"
	fi

	echo "Installing Java for Minecraft..."
# shellcheck disable=SC2086
	$PM_COMMAND "${PM_INSTALL[@]}" $JAVA_PACKAGE &>> "$LOG_FILE"
}

function installDocker {
	if [ "$DOCKER_IS_INSTALLED" ]; then
		echo "Docker already installed. Skipping..."
		return
	fi

	echo "Installing Docker..."

	if [ "$APT_IS_PRESENT" ]; then
		wget -qO- "https://download.docker.com/linux/$ID/gpg" | gpg --dearmor > /usr/share/keyrings/download.docker.com.gpg
		echo "deb [signed-by=/usr/share/keyrings/download.docker.com.gpg arch=amd64] https://download.docker.com/linux/$ID $(lsb_release -cs) stable" > /etc/apt/sources.list.d/download.docker.com.list
		apt-get update &>> "$LOG_FILE"
	elif [ "$YUM_IS_PRESENT" ]; then
		wget -P /etc/yum.repos.d https://download.docker.com/linux/centos/docker-ce.repo &>> "$LOG_FILE"
		yum check-update &>> "$LOG_FILE"
	fi

	{
		$PM_COMMAND "${PM_INSTALL[@]}" docker-ce docker-ce-cli containerd.io
		systemctl enable docker
		systemctl start docker
	} &>> "$LOG_FILE"

	usermod -a -G docker $AMP_SYS_USER &>> "$LOG_FILE"
}

function installSrcdsDeps {
	echo "Installing 32-bit dependencies for srcds..."
	if [ "$APT_IS_PRESENT" ]; then
		dpkg --add-architecture i386 &>> "$LOG_FILE"
		apt-get update &>> "$LOG_FILE"
	fi

# shellcheck disable=SC2086
	$PM_COMMAND "${PM_INSTALL[@]}" $LIB32_PACKAGES &>> "$LOG_FILE"
}

function installNginx {
	echo "Installing nginx and certbot..."

	CERTBOT_IS_PRESENT=$(isPresent certbot)
	if ! [ "$CERTBOT_IS_PRESENT" ] && [ -n "$CERTBOT_PACKAGE" ]; then
		if [ "$YUM_IS_PRESENT" ]; then
			$PM_COMMAND install -y epel-release &>> "$LOG_FILE"
			yum repolist &>> "$LOG_FILE"
		fi
			
		if [ "$APT_IS_PRESENT" ] && [ "$ID" == "ubuntu" ] ; then
			add-apt-repository --yes universe
			apt-get update
		fi

		$PM_COMMAND "${PM_INSTALL[@]}" certbot $CERTBOT_PACKAGE &>> "$LOG_FILE"
	fi

	CERTBOT_IS_PRESENT=$(isPresent certbot)
	if ! [ "$CERTBOT_IS_PRESENT" ]; then
		wget -P /usr/local/bin https://dl.eff.org/certbot-auto &>> "$LOG_FILE"
		chmod +x /usr/local/bin/certbot-auto
	fi

	$PM_COMMAND "${PM_INSTALL[@]}" nginx &>> "$LOG_FILE"
	systemctl enable nginx &>> "$LOG_FILE"
	PROVISIONFLAGS="$PROVISIONFLAGS +Core.Webserver.UsingReverseProxy True"

	if [ "$SELINUX_IS_INSTALLED" ]; then
		echo "Updating SELinux rules (httpd relay)..."
		setsebool -P httpd_can_network_relay 1
		setsebool -P httpd_can_network_connect 1
	fi
}

function installDependencies {
	echo Installing prerequisites...

# shellcheck disable=SC2086
	$PM_COMMAND "${PM_INSTALL[@]}" $PREREQ_PACKAGES &>> "$LOG_FILE"

	JQ_IS_PRESENT="$(isPresent jq)"

	if [[ "$installDocker" =~ ^[Yy]$ ]]; then
		installDocker
		PROVISIONFLAGS="$PROVISIONFLAGS +ADSModule.Defaults.UseDocker True"
		installJava=n
		installsrcdsLibs=n
	fi

	if [[ "$installJava" =~ ^[Yy]$ ]]; then
		installJava
	fi

	if [[ "$installsrcdsLibs" =~ ^[Yy]$ ]]; then
		installSrcdsDeps
	fi

	if [[ "$installDarkMagic" =~ ^[Yy]$ ]]; then
		configureDarkMagicNew
	fi

	if [ -n "$SKIP_INSTALL" ]; then
		setupnginx=n;
		return
	fi	

	if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
		installNginx
	fi
}

function checkConfig {
	if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
		echo -n "Checking settings... "
		domainip=$(dig "$DNS_SERVER" +short "$nginxdomain" | tail -1)

		if [ "$domainip" != "$EXTERNAL_IP" ]; then
			echo "Bad domain configuration."
			if [ -z "$domainip" ]; then
				echo "The specified domain $nginxdomain could not be resolved."
				echo "If you've only recently created the domain or record"
			else
				echo "The specified domain $nginxdomain resolves to '$domainip' but your external IP is '$EXTERNAL_IP'."
				echo "If you've recently changed the IP address this domain resolves to"
			fi
			echo "you may need to empty your DNS cache or wait for DNS propogation to complete."
			echo "Aborting setup. You can re-run this setup to try again."

			exit 100
		else
			echo "Domain $nginxdomain resolves correctly to $domainip."
		fi
	fi
}

function addRepo {
	if [ "$APT_IS_PRESENT" ]; then
		echo "Adding CubeCoders DEB repository..."
		mkdir -p /usr/share/keyrings
		echo "deb [signed-by=/usr/share/keyrings/repo.cubecoders.com.gpg] https://repo.cubecoders.com/$reposuffix debian/" > /etc/apt/sources.list.d/repo.cubecoders.com.list
		{ 
			wget -O /usr/share/keyrings/repo.cubecoders.com.gpg https://repo.cubecoders.com/archive.key;
			apt-get update 
		} &>> "$LOG_FILE"
	elif [ "$YUM_IS_PRESENT" ]; then
		echo "Adding CubeCoders RPM repository..."
		wget -P /etc/yum.repos.d "https://repo.cubecoders.com/${reposuffix}CubeCoders.repo" &>> "$LOG_FILE"
		yum check-update &>> "$LOG_FILE"
	fi
}

function installAMP {
	echo "Installing instance manager..."
	
	if [ "$APT_IS_PRESENT" ] || [ "$YUM_IS_PRESENT" ] ; then
		echo " - Installing via package manager..."
		if ! $PM_COMMAND "${PM_INSTALL[@]}" ampinstmgr &>> "$LOG_FILE"; then
			echo "Failed to install instance manager. Aborting..."
			echo "Possible causes for this are an unsupported distribution, or the repository being in the middle of a sync. In which case wait 30 minutes and try again, re-running the same installation command."
			
			promptLogUpload

			exit 12
		fi
	elif [ "$PACMAN_IS_PRESENT" ]; then
		echo " - Installing from tgz archive..."
		wget -q https://repo.cubecoders.com/ampinstmgr-latest.tgz &>> "$LOG_FILE"
		tar -xf ampinstmgr-latest.tgz -C / &>> "$LOG_FILE"
		rm ampinstmgr-latest.tgz
	fi
}

function addFirewallRule {
	echo "Adding firewall rule for port $1 ($2) via $FIREWALL..."
	case "$FIREWALL" in
		none) echo "No firewall installed, please add port $1 manually to your inbound firewall" ;;
		ufw) ufw allow from any to any port "$1" proto tcp comment "$2" ;;
		firewalld) firewall-cmd "--add-port=$1/tcp" --permanent && firewall-cmd --reload ;;
		iptables) iptables -A INPUT -p tcp -m tcp --dport "$1" -j ACCEPT -m comment --comment "$2" && iptables-save > /etc/iptables/rules.v4 ;;
		nft) nft add rule filter INPUT tcp dport "$1" accept comment "\"$2\"" ;;
		*) echo "Unsupported Firewall!" ;;
	esac
}

function updateFirewall {
	echo Adding firewall rules...
	if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
		addFirewallRule 443 'AMP Reverse Proxy'
		addFirewallRule 80 'AMP Reverse Proxy'
	else
		addFirewallRule $AMP_ADS_PORT 'AMP Management Instance'
	fi
}

function configureNginx {
	echo "{\"status\":200}" > $STATUS_FILE
	
	if ! ampinstmgr setupnginx "$nginxdomain" "$AMP_ADS_PORT" "$nginxemail"; then
		echo "Failed to configure nginx. Please check $LOG_FILE . Aborting..."
		
		promptLogUpload

		exit 19
	fi
}

function createDefaultInstance {
	if [ -n "$SKIP_INSTALL" ]; then
		return
	fi

	if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
		configureNginx
	fi

	echo "Creating default instance..."
	
	if su -l $AMP_SYS_USER -c "EXTERNAL_IP=$EXTERNAL_IP EXT_HOSTNAME=$nginxdomain ampinstmgr quick $ampuser \"$amppass\" $AMP_ADS_IP $AMP_ADS_PORT $PROVISIONFLAGS;exit $?"; then
		systemctl enable ampinstmgr.service
		systemctl enable ampfirewall.service
		systemctl enable ampfirewall.timer
		systemctl enable amptasks.service
		systemctl enable amptasks.timer
		systemctl start ampfirewall.timer
		systemctl start amptasks.timer
	else
		echo "Failed to create default instance."

		if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
			echo "Removing generated nginx config..."
			rm "/etc/nginx/conf.d/$nginxdomain.conf" &>> "$LOG_FILE"
		fi

		echo "Aborting..."

		promptLogUpload

		exit 110
	fi
}

function checkPortAvailable {
	local lines
	lines=$($NS_COMMAND -lnt | grep -c $AMP_ADS_PORT)
	return "$lines"
}

function getNextFreePort {
	while ! checkPortAvailable; do
		AMP_ADS_PORT=$((AMP_ADS_PORT+1))
	done
}

function postSetupHTTPS {
	if ! [ "$AMPINSTMGR_IS_INSTALLED" ]; then
		echo "AMP is not yet installed on this system. Aborting..."
		exit
	fi

	promptForHTTPS
	if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
		checkConfig
		existingInstance=$(su -l $AMP_SYS_USER -c "ampinstmgr status" | grep "ADS" | cut -f 1 -d ' ')
		existingPort=$(su -l $AMP_SYS_USER -c "ampinstmgr status" | grep "ADS" | grep -E -o "[0-9]{4,5}")
		su -l $AMP_SYS_USER -c "ampinstmgr stop $existingInstance"
		su -l $AMP_SYS_USER -c "ampinstmgr rebind $existingInstance 127.0.0.1 $existingPort"
		su -l $AMP_SYS_USER -c "ampinstmgr reconfigure $existingInstance +Core.Webserver.UsingReverseProxy True +ADSModule.Defaults.DefaultAuthServerURL 'http://localhost:$existingPort/'"
		su -l $AMP_SYS_USER -c "ampinstmgr reconfiguremultiple \* +Core.Login.AuthServerURL 'http://localhost:$existingPort/'"
		installNginx
		updateFirewall
		configureNginx
		su -l $AMP_SYS_USER -c "ampinstmgr start $existingInstance"
		cleanup
		echo "Done!"
	fi
}

function update {
	echo "Applying AMP updates..."

	if [ "$APT_IS_PRESENT" ] || [ "$YUM_IS_PRESENT" ] ; then
		$PM_COMMAND update
		$PM_COMMAND "${PM_INSTALL[@]}" ampinstmgr
	elif [ "$PACMAN_IS_PRESENT" ]; then
		installAMP
	fi

	echo "Updating AMP instances..."
	su -l $AMP_SYS_USER -c "ampinstmgr upgradeall"

	echo "Done!"
}

function cleanup {
	rm -f $STATUS_FILE 2> /dev/null
}

if [ -n "$1" ]; then
	
	if ! type "$1" &> /dev/null; then
		echo "No such function $1"
		exit 1
	fi
	$1
	echo "Done"
	exit
fi

function promptLogUpload {
	echo
	echo "Something went wrong during the installation. Would you like to upload your setup log for easy sharing?"
	echo "This will upload $LOG_FILE to the hastebin service and give you a URL you can share."
	echo
	echo "The log file may contain sensitive information such as username, any supplied domain names or your systems hostname"
	echo "so if in doubt - check the file manually and upload it yourself."
	read -n1 -rp "[y/N] " uploadlog
	uploadlog=${uploadlog:-n}

	if [[ "$uploadlog" =~ ^[Yy]$ ]]; then
		PASTE_KEY=$(curl -H "content-type: text/plain" -X POST https://www.toptal.com/developers/hastebin/documents --data-binary "@$LOG_FILE" 2> /dev/null | jq -r .key)
		URL="https://hastebin.com/$PASTE_KEY"
		echo "Log file URL: $URL"
	fi
}

# ENTRY POINT
getNextFreePort
showWelcome

if [ "$AMP_USER_EXISTS" -eq "0" ]; then promptForSystemUser; fi

promptForAMPUser  
promptForDeps
promptForHTTPS

echo
echo "Installation Summary:" | tee $INSTALL_SUMMARY
echo | tee -a $INSTALL_SUMMARY
echo -en "AMP System user:\t\t" | tee -a $INSTALL_SUMMARY
if [ "$AMP_USER_EXISTS" -eq "0" ]; then echo "To be created"; else echo "Already exists"; fi | tee -a $INSTALL_SUMMARY
echo -en "Instance Manager:\t\t"| tee -a $INSTALL_SUMMARY
if [ "$AMPINSTMGR_IS_INSTALLED" ]; then echo "Already installed"; else echo "To be installed"; fi| tee -a $INSTALL_SUMMARY
echo -en "HTTPS setup:\t\t\t"| tee -a $INSTALL_SUMMARY
if [[ "$setupnginx" =~ ^[Yy]$ ]]; then echo "Yes, via nginx with domain $nginxdomain"; else echo "No"; fi| tee -a $INSTALL_SUMMARY
echo -en "Install Java:\t\t\t"| tee -a $INSTALL_SUMMARY
if [[ "$installJava" =~ ^[Yy]$ ]]; then echo "Yes"; else echo "No"; fi | tee -a $INSTALL_SUMMARY
if [ "$ARCH" == "x86_64" ]; then
	echo -en "Install 32-bit libraries:\t" | tee -a $INSTALL_SUMMARY
	if [[ "$installsrcdsLibs" =~ ^[Yy]$ ]]; then echo "Yes"; else echo "No"; fi | tee -a $INSTALL_SUMMARY
	echo -en "Install Docker:\t\t\t" | tee -a $INSTALL_SUMMARY
	if [[ "$installDocker" =~ ^[Yy]$ ]]; then echo "Yes"; else echo "No"; fi | tee -a $INSTALL_SUMMARY
fi
if [ "$ARCH" == "aarch64" ]; then
	echo -en "Configure CPx2:\t\t\t" | tee -a $INSTALL_SUMMARY
	if [[ "$installDarkMagic" =~ ^[Yy]$ ]]; then echo "Yes"; else echo "No"; fi | tee -a $INSTALL_SUMMARY
fi

if [ -z "$USE_ANSWERS" ]; then
	echo 
	echo "Ready to install AMP. Press ENTER to continue or CTRL+C to cancel."
	read -r
	echo
fi

echo Installing AMP...

if [ "$AMP_USER_EXISTS" -eq "0" ]; then
	createUser
else
	echo "$AMP_SYS_USER already exists. Skipping..."

	if [ "$AMPINSTMGR_IS_INSTALLED" ]; then
		if [ "$(su -l $AMP_SYS_USER -c 'ampinstmgr status | grep -c "│"')" -gt 1 ]; then
			echo "$AMP_SYS_USER already has instances. AMP appears to be already installed and configured. Aborting..."
			exit 135
		fi
	fi
fi

updateSystem
installDependencies
checkConfig

if ! [ "$AMPINSTMGR_IS_INSTALLED" ]; then
	addRepo
	installAMP
else
	echo "AMP instance manager already installed. Skipping..."
fi

updateFirewall
createDefaultInstance
cleanup

echo
echo "Installation complete. Thanks for using AMP!"
echo

if [[ "$setupnginx" =~ ^[Yy]$ ]]; then
	echo "You can now reach AMP at https://$nginxdomain/"
	echo
	echo "https://$nginxdomain/" | qrencode -t UTF8 -m 2 | sed -e "6s|$|	Scan this code or visit https://$nginxdomain/|" -e "7s|$|	to start using AMP from your mobile device.|"
	echo
elif [ "$INTERNAL_IP" == "$EXTERNAL_IP" ]; then
	echo "You can now reach AMP at http://$INTERNAL_IP:$AMP_ADS_PORT/"
	echo
	echo "http://$INTERNAL_IP:$AMP_ADS_PORT/" | qrencode -t UTF8 -m 2 | sed -e "6s|$|	Scan this code or visit http://$INTERNAL_IP:$AMP_ADS_PORT/|" -e "7s|$|	to start using AMP from your mobile device.|"
	echo
else
	echo "You can now reach AMP at http://$INTERNAL_IP:$AMP_ADS_PORT/"
	echo "or at http://$EXTERNAL_IP:$AMP_ADS_PORT/"
	echo
	echo "http://$INTERNAL_IP:$AMP_ADS_PORT/" | qrencode -t UTF8 -m 2 | sed -e "6s|$|	Scan this code or visit http://$INTERNAL_IP:$AMP_ADS_PORT/|" -e "7s|$|	to start using AMP from your mobile device.|" -e "8s|$|	(You must be connected to the same network as the server)|"
	echo
fi
