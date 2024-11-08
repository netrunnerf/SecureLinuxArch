# SecureLinuxArch
Configuration for increase security of Arch Linux

# SecureLinuxArch
Configuration for increase security of Arch Linux

Sure! Below is a secure kernel configuration guide that you can include in your GitHub README. This guide focuses on customizing and hardening the Linux kernel to enhance the security of your Arch Linux system.

---

# Secure Kernel Configuration Guide

This guide provides detailed instructions on how to configure and build a secure Linux kernel for your Arch Linux system. By customizing the kernel configuration, you can enable security features and hardening options that reduce the attack surface and protect against various threats.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: Install Required Packages](#step-1-install-required-packages)
- [Step 2: Download the Kernel Source](#step-2-download-the-kernel-source)
- [Step 3: Prepare for Configuration](#step-3-prepare-for-configuration)
- [Step 4: Configure the Kernel](#step-4-configure-the-kernel)
  - [Enable Security Features](#enable-security-features)
  - [Disable Unnecessary Features](#disable-unnecessary-features)
- [Step 5: Build and Install the Kernel](#step-5-build-and-install-the-kernel)
- [Step 6: Update Bootloader Configuration](#step-6-update-bootloader-configuration)
- [Step 7: Verify the New Kernel](#step-7-verify-the-new-kernel)
- [Maintenance and Updates](#maintenance-and-updates)
- [References](#references)

---

## Introduction

Customizing the Linux kernel allows you to tailor your system to specific security needs. By enabling certain security features and disabling unnecessary components, you can enhance the overall security posture of your system.

---

## Prerequisites

- Arch Linux installed and fully updated.
- Basic knowledge of compiling software from source.
- Sufficient disk space (at least 20 GB free) and processing power.
- A backup of important data.

---

## Step 1: Install Required Packages

Install the necessary packages for building the kernel:

```bash
sudo pacman -Syu
sudo pacman -S base-devel git ncurses openssl bc kmod cpio flex bison libelf pahole
```

---

## Step 2: Download the Kernel Source

Choose one of the following methods:

### Option A: Download the Latest Stable Kernel

```bash
cd /usr/src
sudo wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.x.y.tar.xz
sudo tar -xvf linux-6.x.y.tar.xz
cd linux-6.x.y
```

### Option B: Clone the Stable Git Repository

```bash
cd /usr/src
sudo git clone --depth=1 --branch v6.x.y https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
cd linux
```

---

## Step 3: Prepare for Configuration

Copy the current kernel configuration as a starting point:

```bash
sudo cp /boot/config-$(uname -r) .config
sudo make oldconfig
```

---

## Step 4: Configure the Kernel

Launch the kernel configuration menu:

```bash
sudo make menuconfig
```

### Enable Security Features

#### 1. Enable Stack Protector Strong

- **Path**: `Compiler options` → `Stack Protector buffer overflow detection`
- **Set**: `Strong Stack Protector` (`CONFIG_STACKPROTECTOR_STRONG=y`)

#### 2. Enable Kernel Address Space Layout Randomization (KASLR)

- **Path**: `Processor type and features` → `Randomize the address of the kernel image (KASLR)`
- **Set**: (`CONFIG_RANDOMIZE_BASE=y`)

#### 3. Enable Restrict /dev/mem Access

- **Path**: `Device Drivers` → `Character devices` → `Enable /dev/mem virtual device support`
- **Set**: Restrict access (`CONFIG_STRICT_DEVMEM=y`)

#### 4. Enable Module Signature Verification

- **Path**: `Enable loadable module support` → `Module signature verification`
- **Set**:
  - Require modules to be validly signed (`CONFIG_MODULE_SIG_FORCE=y`)
  - Automatically sign all modules (`CONFIG_MODULE_SIG_ALL=y`)

#### 5. Enable SELinux Support (Optional)

- **Path**: `Security options` → `NSA SELinux Support`
- **Set**: (`CONFIG_SECURITY_SELINUX=y`)

#### 6. Enable AppArmor Support (Optional, if not using SELinux)

- **Path**: `Security options` → `AppArmor support`
- **Set**: (`CONFIG_SECURITY_APPARMOR=y`)

#### 7. Enable Seccomp

- **Path**: `General setup` → `Enable seccomp to safely compute untrusted bytecode`
- **Set**: (`CONFIG_SECCOMP=y`)

#### 8. Enable Hardened Usercopy

- **Path**: `Security options` → `Harden memory copies between kernel and userspace`
- **Set**: (`CONFIG_HARDENED_USERCOPY=y`)

#### 9. Enable Integrity Measurement Architecture (IMA)

- **Path**: `Security options` → `Integrity subsystem` → `Integrity Measurement Architecture(IMA)`
- **Set**: (`CONFIG_IMA=y`)

#### 10. Enable Linux Security Module (LSM) Stacking

- **Path**: `Security options` → `LSM support`
- **Set**: Choose multiple LSMs as needed (`CONFIG_LSM="selinux,apparmor,yama,loadpin,safesetid,integrity"`)

### Disable Unnecessary Features

#### 1. Disable Unused Filesystems

- **Path**: `File systems`
- **Action**: Disable filesystems you do not use (e.g., `Minix`, `HFS`, `BeFS`).

#### 2. Disable Unused Network Protocols

- **Path**: `Networking support` → `Networking options`
- **Action**: Disable protocols like `DCCP`, `SCTP`, `RDS`, `TIPC`, `DECnet`, `Appletalk`.

#### 3. Disable Unnecessary Drivers

- **Path**: `Device Drivers`
- **Action**: Disable drivers for hardware not present in your system.

#### 4. Disable Kernel Debugging Features

- **Path**: `Kernel hacking`
- **Action**: Unless needed, disable debugging options to reduce kernel size and attack surface.

---

## Step 5: Build and Install the Kernel

### Clean Build Environment

```bash
sudo make clean
sudo make mrproper
```

### Build the Kernel

```bash
sudo make -j$(nproc)
```

### Install Modules

```bash
sudo make modules_install
```

### Install the Kernel

```bash
sudo make install
```

This installs the kernel and updates files in `/boot`:

- `vmlinuz-6.x.y`
- `initramfs-6.x.y.img`
- `System.map-6.x.y`

---

## Step 6: Update Bootloader Configuration

### For GRUB Users

1. **Update GRUB Configuration**:

   ```bash
   sudo grub-mkconfig -o /boot/grub/grub.cfg
   ```

2. **Verify GRUB Entries**:

   Check that the new kernel version appears in `/boot/grub/grub.cfg`.

---

## Step 7: Verify the New Kernel

### Reboot the System

```bash
sudo reboot
```

### Check Kernel Version

After rebooting, confirm that the system is running the new kernel:

```bash
uname -r
```

### Verify Enabled Security Features

#### Check for KASLR

```bash
dmesg | grep "Kernel Offset"
```

A non-zero offset indicates KASLR is active.

#### Verify Stack Protector

```bash
grep CONFIG_STACKPROTECTOR_STRONG /boot/config-$(uname -r)
```

Output should be `CONFIG_STACKPROTECTOR_STRONG=y`.

#### Check SELinux/AppArmor Status

- **For SELinux**:

  ```bash
  sestatus
  ```

- **For AppArmor**:

  ```bash
  sudo aa-status
  ```

#### Verify Module Signature Enforcement

Attempt to load an unsigned module to confirm enforcement:

```bash
sudo insmod ./unsigned_module.ko
```

You should receive a permission denied error.

---

## Maintenance and Updates

- **Keep the Kernel Updated**: Regularly check for new kernel releases and security patches.
- **Backup Configuration**: Save your `.config` file for future use:

  ```bash
  sudo cp .config ~/secure_kernel_config_$(uname -r)
  ```

- **Monitor Security Advisories**: Stay informed about vulnerabilities and apply patches promptly.

---

## References

- [Arch Linux Kernel Compilation](https://wiki.archlinux.org/title/Kernel/Traditional_compilation)
- [Kernel Self-Protection Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
- [Linux Kernel Configuration Guide](https://www.kernel.org/doc/html/latest/admin-guide/index.html)
- [Security Features of the Linux Kernel](https://www.linuxfoundation.org/blog/classic-security-features-of-the-linux-kernel)

---

By following this guide, you have configured and built a Linux kernel with enhanced security features tailored to your system. Regular updates and maintenance are essential to ensure ongoing protection against emerging threats.

Sure! Below is a comprehensive guide on secure network configuration for your Arch Linux system. This guide is designed to help you enhance the security of your network settings and can be included in your GitHub README.

---

# Secure Network Configuration Guide

This guide provides detailed instructions on how to securely configure network settings on your Arch Linux system. By implementing these configurations, you can protect your system from network-based attacks and ensure secure communication.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: Update the System](#step-1-update-the-system)
- [Step 2: Configure the Firewall](#step-2-configure-the-firewall)
  - [Option A: Using UFW (Uncomplicated Firewall)](#option-a-using-ufw-uncomplicated-firewall)
  - [Option B: Using nftables](#option-b-using-nftables)
- [Step 3: Secure SSH Configuration](#step-3-secure-ssh-configuration)
- [Step 4: Disable Unused Network Services](#step-4-disable-unused-network-services)
- [Step 5: Configure Network Kernel Parameters](#step-5-configure-network-kernel-parameters)
- [Step 6: Implement Intrusion Detection](#step-6-implement-intrusion-detection)
- [Step 7: Use Fail2ban to Prevent Brute Force Attacks](#step-7-use-fail2ban-to-prevent-brute-force-attacks)
- [Step 8: Configure DNS Security](#step-8-configure-dns-security)
- [Step 9: Enable Network Time Protocol (NTP) Security](#step-9-enable-network-time-protocol-ntp-security)
- [Maintenance and Monitoring](#maintenance-and-monitoring)
- [References](#references)

---

## Introduction

Securing network configurations is critical to protecting your system from unauthorized access and network-based threats. This guide will walk you through setting up a robust firewall, securing SSH access, hardening network parameters, and implementing additional security measures.

---

## Prerequisites

- Arch Linux installed and fully updated.
- Basic knowledge of command-line operations.
- Administrative (root) privileges.
- Internet connection for installing packages.

---

## Step 1: Update the System

Ensure your system is up to date:

```bash
sudo pacman -Syu
```

---

## Step 2: Configure the Firewall

A firewall controls incoming and outgoing network traffic based on predetermined security rules. Arch Linux does not enable a firewall by default, so you need to set one up.

### Option A: Using UFW (Uncomplicated Firewall)

#### Install UFW

```bash
sudo pacman -S ufw
```

#### Enable UFW Service

```bash
sudo systemctl enable ufw
sudo systemctl start ufw
```

#### Set Default Policies

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

#### Allow Essential Services (Optional)

If you need SSH access:

```bash
sudo ufw allow ssh
```

#### Enable the Firewall

```bash
sudo ufw enable
```

#### Check UFW Status

```bash
sudo ufw status verbose
```

### Option B: Using nftables

#### Install nftables

```bash
sudo pacman -S nftables
```

#### Create nftables Configuration

Create a file `/etc/nftables.conf` with the following content:

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0;
        policy drop;

        # Accept any localhost traffic
        iif lo accept

        # Accept established and related connections
        ct state established,related accept

        # Accept SSH (Optional)
        tcp dport ssh accept

        # ICMP (Ping)
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
```

#### Enable nftables Service

```bash
sudo systemctl enable nftables
sudo systemctl start nftables
```

#### Verify nftables Rules

```bash
sudo nft list ruleset
```

---

## Step 3: Secure SSH Configuration

If you use SSH for remote access, it's crucial to secure it to prevent unauthorized logins.

#### Install OpenSSH

```bash
sudo pacman -S openssh
```

#### Edit SSH Configuration

Open `/etc/ssh/sshd_config` in a text editor:

```bash
sudo nano /etc/ssh/sshd_config
```

#### Recommended Settings

- **Disable Root Login**

  ```ini
  PermitRootLogin no
  ```

- **Disable Password Authentication (Use SSH Keys Instead)**

  ```ini
  PasswordAuthentication no
  ```

- **Change Default SSH Port (Optional)**

  ```ini
  Port 2222
  ```

- **Limit SSH Access to Specific Users**

  ```ini
  AllowUsers your_username
  ```

- **Disable Empty Passwords**

  ```ini
  PermitEmptyPasswords no
  ```

- **Enable Protocol 2 Only**

  ```ini
  Protocol 2
  ```

- **Use Strong Ciphers and MACs**

  Add or modify the following lines:

  ```ini
  Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  ```

#### Restart SSH Service

```bash
sudo systemctl restart sshd
```

---

## Step 4: Disable Unused Network Services

List all active services:

```bash
sudo systemctl list-units --type=service --state=running
```

Disable any unnecessary network services:

```bash
sudo systemctl disable service-name
sudo systemctl stop service-name
```

---

## Step 5: Configure Network Kernel Parameters

Adjusting network-related kernel parameters can enhance security.

#### Create sysctl Configuration File

Create `/etc/sysctl.d/99-network-security.conf` with the following content:

```ini
# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not used
# net.ipv6.conf.all.disable_ipv6 = 1

# Enable protection against SYN flood attacks
net.ipv4.tcp_max_syn_backlog = 2048

# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1

# Enable ignoring broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable packet forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
```

#### Apply the Settings

```bash
sudo sysctl --system
```

---

## Step 6: Implement Intrusion Detection

Install tools to monitor network activity.

#### Install Snort (Network Intrusion Detection System)

```bash
sudo pacman -S snort
```

#### Basic Configuration of Snort

Edit `/etc/snort/snort.conf` to set up basic rules and configurations. Refer to the [Snort documentation](https://www.snort.org/documents) for detailed instructions.

---

## Step 7: Use Fail2ban to Prevent Brute Force Attacks

Fail2ban scans log files and bans IPs that show malicious signs.

#### Install Fail2ban

```bash
sudo pacman -S fail2ban
```

#### Configure Fail2ban

Edit `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled = true
port    = 2222   # Change if you altered the SSH port
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
```

#### Start and Enable Fail2ban

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## Step 8: Configure DNS Security

#### Use Trusted DNS Servers

Edit `/etc/resolv.conf`:

```ini
nameserver 1.1.1.1     # Cloudflare DNS
nameserver 9.9.9.9     # Quad9 DNS
```

#### Prevent DNS Cache Poisoning

Install and configure a local DNS resolver like Unbound:

```bash
sudo pacman -S unbound
```

Configure `/etc/unbound/unbound.conf` according to security best practices. Refer to the [Unbound documentation](https://nlnetlabs.nl/documentation/unbound/) for detailed instructions.

---

## Step 9: Enable Network Time Protocol (NTP) Security

Time synchronization is essential for security protocols.

#### Install Chrony

```bash
sudo pacman -S chrony
```

#### Configure Chrony

Edit `/etc/chrony.conf`:

```ini
# Use public NTP servers
pool pool.ntp.org iburst

# Allow only the local system to query the time
allow 127.0.0.1

# Ignore all other NTP packets
cmdallow 127.0.0.1
```

#### Start and Enable Chrony

```bash
sudo systemctl enable chronyd
sudo systemctl start chronyd
```

---

## Maintenance and Monitoring

- **Regular Updates**: Keep your system and packages updated.

  ```bash
  sudo pacman -Syu
  ```

- **Monitor Logs**: Regularly check system and application logs for suspicious activities.

  ```bash
  sudo journalctl -xe
  ```

- **Test Firewall Rules**: Periodically test your firewall to ensure it's functioning correctly.

- **Audit Network Ports**: Use tools like `nmap` to scan your system for open ports.

  ```bash
  sudo pacman -S nmap
  nmap -sTU -O localhost
  ```

- **Use Network Monitoring Tools**: Install tools like `iftop` or `vnStat` to monitor network traffic.

  ```bash
  sudo pacman -S iftop vnstat
  ```

---

## References

- [Arch Linux Network Configuration](https://wiki.archlinux.org/title/Network_configuration)
- [Arch Linux Security Guide](https://wiki.archlinux.org/title/Security)
- [UFW Arch Wiki](https://wiki.archlinux.org/title/UFW)
- [nftables Arch Wiki](https://wiki.archlinux.org/title/Nftables)
- [OpenSSH Arch Wiki](https://wiki.archlinux.org/title/OpenSSH)
- [sysctl Networking](https://www.kernel.org/doc/Documentation/networking/sysctl.txt)
- [Fail2ban Arch Wiki](https://wiki.archlinux.org/title/Fail2ban)
- [Chrony Arch Wiki](https://wiki.archlinux.org/title/Chrony)
- [Snort Official Documentation](https://www.snort.org/documents)

---

By following this guide, you have enhanced the network security of your Arch Linux system. Regular maintenance and monitoring are essential to maintain a secure environment. Feel free to adjust configurations to suit your specific needs, and always test changes in a controlled setting before deploying them on critical systems.
