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

Certainly! Below is a comprehensive guide on setting up LUKS (Linux Unified Key Setup) encryption for your Arch Linux system. This guide is designed to help you encrypt your disks using LUKS during the installation process, enhancing the security of your data. You can include this guide in your GitHub README.

---

# Disk Encryption with LUKS Guide

This guide provides detailed instructions on how to set up full disk encryption using LUKS on Arch Linux. Encrypting your disks ensures that your data remains secure and inaccessible to unauthorized users, especially in the event of physical theft.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Understanding LUKS Encryption](#understanding-luks-encryption)
- [Step 1: Boot from Arch Linux Installation Media](#step-1-boot-from-arch-linux-installation-media)
- [Step 2: Prepare the Disk](#step-2-prepare-the-disk)
  - [Option A: Using GPT with UEFI](#option-a-using-gpt-with-uefi)
  - [Option B: Using MBR with BIOS](#option-b-using-mbr-with-bios)
- [Step 3: Encrypt the Partition with LUKS](#step-3-encrypt-the-partition-with-luks)
- [Step 4: Set Up LVM on LUKS (Optional)](#step-4-set-up-lvm-on-luks-optional)
- [Step 5: Format and Mount Filesystems](#step-5-format-and-mount-filesystems)
- [Step 6: Install the Base System](#step-6-install-the-base-system)
- [Step 7: Configure the System](#step-7-configure-the-system)
- [Step 8: Configure mkinitcpio](#step-8-configure-mkinitcpio)
- [Step 9: Configure the Bootloader](#step-9-configure-the-bootloader)
- [Step 10: Finalize the Installation](#step-10-finalize-the-installation)
- [Maintenance and Tips](#maintenance-and-tips)
- [References](#references)

---

## Introduction

LUKS is the standard for Linux disk encryption. It provides a standard on-disk format, facilitating compatibility among distributions and enabling secure management of multiple user passwords.

This guide walks you through encrypting your root partition during a fresh Arch Linux installation. It covers both UEFI/GPT and BIOS/MBR setups and includes optional steps for using LVM (Logical Volume Manager) on top of LUKS.

---

## Prerequisites

- Arch Linux installation media (USB or CD).
- Basic understanding of Linux command-line operations.
- Familiarity with disk partitioning concepts.
- A backup of any important data on the target disk.

---

## Understanding LUKS Encryption

- **LUKS (Linux Unified Key Setup):** A standard for disk encryption that uses the kernel's dm-crypt subsystem.
- **Benefits of LUKS:**
  - Supports multiple keys/passwords.
  - Provides strong encryption (uses cryptographic algorithms like AES).
  - Integrates with the kernel's device mapper subsystem.

---

## Step 1: Boot from Arch Linux Installation Media

1. **Insert the installation media** and boot the system.
2. **Select the Arch Linux installation option** from the boot menu.

---

## Step 2: Prepare the Disk

### Identify the Target Disk

List all disks to identify your target disk (e.g., `/dev/sda`):

```bash
lsblk
```

### Option A: Using GPT with UEFI

#### Partition the Disk Using `gdisk` or `cgdisk`

```bash
gdisk /dev/sda
```

#### Create Partitions

- **EFI System Partition (ESP):** 512 MiB, type `ef00`.
- **Boot Partition (Optional):** 1 GiB, type `8300`.
- **Root Partition:** Remaining space, type `8300`.

**Example Partition Table:**

| Partition | Size      | Type | Description              |
|-----------|-----------|------|--------------------------|
| /dev/sda1 | 512 MiB   | ef00 | EFI System Partition     |
| /dev/sda2 | 1 GiB     | 8300 | /boot (unencrypted)      |
| /dev/sda3 | Rest of disk | 8300 | Encrypted root partition |

### Option B: Using MBR with BIOS

#### Partition the Disk Using `fdisk`

```bash
fdisk /dev/sda
```

#### Create Partitions

- **Boot Partition (Optional):** 1 GiB, type `83`.
- **Root Partition:** Remaining space, type `83`.

---

## Step 3: Encrypt the Partition with LUKS

### Initialize LUKS on the Root Partition

**Replace `/dev/sda3` with your actual root partition.**

```bash
cryptsetup luksFormat /dev/sda3
```

- **Warning:** This will erase all data on the partition.
- **Enter a strong passphrase** when prompted.

### Open the Encrypted Partition

```bash
cryptsetup open /dev/sda3 cryptroot
```

- This creates a decrypted mapping at `/dev/mapper/cryptroot`.

---

## Step 4: Set Up LVM on LUKS (Optional)

Using LVM allows for flexible disk management.

### Create a Physical Volume

```bash
pvcreate /dev/mapper/cryptroot
```

### Create a Volume Group

```bash
vgcreate vg0 /dev/mapper/cryptroot
```

### Create Logical Volumes

- **Swap Volume (Optional):**

  ```bash
  lvcreate -L 4G vg0 -n swap
  ```

- **Root Volume:**

  ```bash
  lvcreate -l 100%FREE vg0 -n root
  ```

---

## Step 5: Format and Mount Filesystems

### Format the Partitions

- **EFI System Partition (ESP):**

  ```bash
  mkfs.fat -F32 /dev/sda1
  ```

- **Boot Partition (If created):**

  ```bash
  mkfs.ext4 /dev/sda2
  ```

- **Root Partition:**

  - **If using LVM:**

    ```bash
    mkfs.ext4 /dev/vg0/root
    ```

  - **If not using LVM:**

    ```bash
    mkfs.ext4 /dev/mapper/cryptroot
    ```

- **Swap Partition (If using LVM):**

  ```bash
  mkswap /dev/vg0/swap
  ```

### Mount the Filesystems

- **Mount Root Partition:**

  - **With LVM:**

    ```bash
    mount /dev/vg0/root /mnt
    ```

  - **Without LVM:**

    ```bash
    mount /dev/mapper/cryptroot /mnt
    ```

- **Mount Boot Partition (If created):**

  ```bash
  mkdir /mnt/boot
  mount /dev/sda2 /mnt/boot
  ```

- **Mount EFI System Partition:**

  ```bash
  mkdir /mnt/boot/efi
  mount /dev/sda1 /mnt/boot/efi
  ```

- **Enable Swap (If created):**

  ```bash
  swapon /dev/vg0/swap
  ```

---

## Step 6: Install the Base System

```bash
pacstrap /mnt base linux linux-firmware
```

- **Optional:** Install additional packages like `base-devel`, `vim`, `sudo`.

---

## Step 7: Configure the System

### Generate fstab

```bash
genfstab -U /mnt >> /mnt/etc/fstab
```

### Chroot into the System

```bash
arch-chroot /mnt
```

### Set the Timezone

```bash
ln -sf /usr/share/zoneinfo/Region/City /etc/localtime
hwclock --systohc
```

### Localization

Edit `/etc/locale.gen` and uncomment your locale (e.g., `en_US.UTF-8 UTF-8`):

```bash
nano /etc/locale.gen
```

Generate the locales:

```bash
locale-gen
```

Set the `LANG` variable:

```bash
echo "LANG=en_US.UTF-8" > /etc/locale.conf
```

### Set the Hostname

```bash
echo "your_hostname" > /etc/hostname
```

Update `/etc/hosts`:

```ini
127.0.0.1   localhost
::1         localhost
127.0.1.1   your_hostname.localdomain your_hostname
```

---

## Step 8: Configure mkinitcpio

Edit `/etc/mkinitcpio.conf`:

```bash
nano /etc/mkinitcpio.conf
```

### Modify the HOOKS Array

- **For LUKS without LVM:**

  ```ini
  HOOKS=(base udev autodetect modconf block encrypt filesystems keyboard fsck)
  ```

- **For LUKS with LVM:**

  ```ini
  HOOKS=(base udev autodetect modconf block encrypt lvm2 filesystems keyboard fsck)
  ```

### Regenerate the initramfs

```bash
mkinitcpio -P
```

---

## Step 9: Configure the Bootloader

### Install GRUB and Required Packages

```bash
pacman -S grub efibootmgr dosfstools os-prober mtools
```

- **If using BIOS/MBR, you can skip `efibootmgr` and `mtools`.**

### Install GRUB

- **For UEFI Systems:**

  ```bash
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
  ```

- **For BIOS Systems:**

  ```bash
  grub-install --target=i386-pc /dev/sda
  ```

### Configure GRUB for LUKS

Edit `/etc/default/grub`:

```bash
nano /etc/default/grub
```

Add the following to `GRUB_CMDLINE_LINUX`:

- **Without LVM:**

  ```ini
  GRUB_CMDLINE_LINUX="cryptdevice=UUID=your_partition_uuid:cryptroot root=/dev/mapper/cryptroot"
  ```

- **With LVM:**

  ```ini
  GRUB_CMDLINE_LINUX="cryptdevice=UUID=your_partition_uuid:cryptlvm root=/dev/vg0/root"
  ```

- **Find the UUID:**

  ```bash
  blkid /dev/sda3
  ```

### Generate GRUB Configuration

```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

---

## Step 10: Finalize the Installation

### Set the Root Password

```bash
passwd
```

### Create a New User (Optional)

```bash
useradd -m -G wheel -s /bin/bash your_username
passwd your_username
```

Edit sudoers file to grant sudo access:

```bash
EDITOR=nano visudo
```

Uncomment:

```ini
%wheel ALL=(ALL) ALL
```

### Exit chroot and Reboot

```bash
exit
umount -R /mnt
reboot
```

---

## Maintenance and Tips

### Backup LUKS Header

It's crucial to backup the LUKS header to prevent data loss if it becomes corrupted.

```bash
cryptsetup luksHeaderBackup /dev/sda3 --header-backup-file luks-header-backup.img
```

Store this backup in a secure location.

### Add Additional Passphrases

You can add more passphrases to the LUKS container:

```bash
cryptsetup luksAddKey /dev/sda3
```

### Change or Remove Passphrases

- **Change Passphrase:**

  ```bash
  cryptsetup luksChangeKey /dev/sda3
  ```

- **Remove Passphrase:**

  ```bash
  cryptsetup luksRemoveKey /dev/sda3
  ```

### Check LUKS Status

```bash
cryptsetup -v status cryptroot
```

### Encrypt Additional Partitions

Repeat the encryption steps for any additional partitions you wish to encrypt.

---

## References

- [Arch Linux Installation Guide](https://wiki.archlinux.org/title/Installation_guide)
- [Arch Linux LUKS Encryption](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system)
- [GRUB Encryption with LUKS](https://wiki.archlinux.org/title/GRUB#Encrypted_/boot)
- [LVM on LUKS](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system#Encrypted_LVM)
- [cryptsetup Manual](https://man.archlinux.org/man/cryptsetup.8)

---

By following this guide, you have set up full disk encryption using LUKS on your Arch Linux system. This enhances the security of your data, ensuring that it remains protected even if the physical device is compromised.

Certainly! Below is a comprehensive guide on physical security measures for your Arch Linux system. This guide focuses on protecting your hardware and data from physical threats and can be included in your GitHub README.

---

# Physical Security Guide

This guide provides detailed instructions on implementing physical security measures to protect your Arch Linux system. Physical security is a critical component of overall system security, ensuring that unauthorized individuals cannot gain physical access to your hardware and sensitive data.

## Table of Contents

- [Introduction](#introduction)
- [Understanding Physical Security Threats](#understanding-physical-security-threats)
- [Step 1: Secure the Hardware](#step-1-secure-the-hardware)
  - [1.1: Use Lockable Cases](#11-use-lockable-cases)
  - [1.2: Secure Hardware Location](#12-secure-hardware-location)
  - [1.3: BIOS/UEFI Security](#13-biosuefi-security)
- [Step 2: Implement Boot Security](#step-2-implement-boot-security)
  - [2.1: Set BIOS/UEFI Passwords](#21-set-biosuefi-passwords)
  - [2.2: Disable Boot from External Media](#22-disable-boot-from-external-media)
  - [2.3: Enable Secure Boot (Optional)](#23-enable-secure-boot-optional)
- [Step 3: Protect Data at Rest](#step-3-protect-data-at-rest)
  - [3.1: Full Disk Encryption with LUKS](#31-full-disk-encryption-with-luks)
  - [3.2: Encrypt Swap and Temporary Filesystems](#32-encrypt-swap-and-temporary-filesystems)
- [Step 4: Physical Access Controls](#step-4-physical-access-controls)
  - [4.1: Access Control Systems](#41-access-control-systems)
  - [4.2: Surveillance and Monitoring](#42-surveillance-and-monitoring)
- [Step 5: Implement Hardware-Based Security Modules](#step-5-implement-hardware-based-security-modules)
  - [5.1: Trusted Platform Module (TPM)](#51-trusted-platform-module-tpm)
  - [5.2: Hardware Security Keys](#52-hardware-security-keys)
- [Step 6: Regular Maintenance and Audits](#step-6-regular-maintenance-and-audits)
- [References](#references)

---

## Introduction

While software security measures are essential, they can be undermined if an attacker gains physical access to your system. Physical security involves safeguarding the hardware and the environment in which it operates, thereby preventing unauthorized physical access, damage, or interference.

---

## Understanding Physical Security Threats

Common physical security threats include:

- **Theft of Equipment**: Unauthorized removal of hardware.
- **Unauthorized Access**: Physical access to the system leading to data breaches.
- **Hardware Tampering**: Insertion of malicious hardware or modification of components.
- **Environmental Hazards**: Damage due to fire, water, or extreme temperatures.

Understanding these threats helps in implementing appropriate security measures.

---

## Step 1: Secure the Hardware

### 1.1: Use Lockable Cases

**Action**: Use computer cases that can be locked to prevent unauthorized opening.

- **Benefits**:
  - Prevents physical tampering with internal components.
  - Deters insertion of hardware keyloggers or malicious devices.

**Implementation**:

- Choose cases with lock mechanisms.
- Keep keys secure and limit access to authorized personnel.

### 1.2: Secure Hardware Location

**Action**: Place your hardware in a secure, restricted area.

- **Benefits**:
  - Limits physical access to trusted individuals.
  - Reduces risk of theft or tampering.

**Implementation**:

- Use locked rooms or cabinets.
- Install security cameras in sensitive areas.
- Implement access control systems (e.g., keycards, biometric scanners).

### 1.3: BIOS/UEFI Security

**Action**: Secure the BIOS/UEFI firmware settings to prevent unauthorized changes.

- **Benefits**:
  - Prevents boot sequence changes.
  - Blocks unauthorized access to hardware settings.

**Implementation**:

- **Update Firmware**: Ensure BIOS/UEFI firmware is up to date to patch vulnerabilities.

  ```bash
  # Check for firmware updates from your hardware manufacturer.
  ```

- **Set Administrator Password**:

  - Access BIOS/UEFI settings during boot (usually by pressing `F2`, `Delete`, or `F12`).
  - Navigate to the security settings.
  - Set a strong administrator password.

- **Set Boot Password** (Optional):

  - Enable a password prompt every time the system boots.
  - **Note**: May inconvenience legitimate users.

---

## Step 2: Implement Boot Security

### 2.1: Set BIOS/UEFI Passwords

**Action**: As above, set passwords to prevent unauthorized access to BIOS/UEFI settings and the boot process.

### 2.2: Disable Boot from External Media

**Action**: Prevent the system from booting from USB drives, CDs, or other external media.

- **Benefits**:
  - Stops attackers from using live systems to bypass security measures.

**Implementation**:

- Access BIOS/UEFI settings.
- Set the boot order to prioritize the internal drive.
- Disable boot options for external devices.
- Lock BIOS/UEFI with a password to prevent changes.

### 2.3: Enable Secure Boot (Optional)

**Action**: Use UEFI Secure Boot to ensure only trusted software loads during the boot process.

- **Benefits**:
  - Prevents bootkits and rootkits from loading before the operating system.
  - Ensures integrity of the bootloader and kernel.

**Implementation**:

- Access BIOS/UEFI settings.
- Enable Secure Boot.
- Configure your bootloader (e.g., GRUB) and kernel to support Secure Boot.
- **Note**: Setting up Secure Boot on Arch Linux can be complex.

  - **References**:
    - [Arch Linux Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)

---

## Step 3: Protect Data at Rest

### 3.1: Full Disk Encryption with LUKS

**Action**: Encrypt the entire disk using LUKS to protect data if the physical drive is accessed.

- **Benefits**:
  - Prevents data access if the drive is removed.
  - Protects sensitive information from unauthorized access.

**Implementation**:

- Follow the [Disk Encryption with LUKS Guide](#) provided earlier.

### 3.2: Encrypt Swap and Temporary Filesystems

**Action**: Ensure that swap partitions and temporary filesystems are encrypted.

- **Benefits**:
  - Prevents sensitive data from being written to unencrypted areas.

**Implementation**:

- **Encrypt Swap**:

  - If using LVM:

    ```bash
    lvcreate -L 4G vg0 -n swap
    mkswap /dev/vg0/swap
    ```

  - Add swap encryption options in `/etc/crypttab` and `/etc/fstab`.

- **Use tmpfs for /tmp**:

  - Add the following line to `/etc/fstab`:

    ```ini
    tmpfs /tmp tmpfs defaults,noatime,mode=1777 0 0
    ```

---

## Step 4: Physical Access Controls

### 4.1: Access Control Systems

**Action**: Implement physical access control mechanisms to restrict entry to areas where hardware is stored.

- **Benefits**:
  - Limits access to authorized personnel.
  - Provides audit trails of access events.

**Implementation**:

- **Keycard Systems**: Use electronic keycards or fobs.
- **Biometric Systems**: Fingerprint or retina scanners.
- **Security Guards**: Employ personnel to monitor access points.
- **Visitor Logs**: Maintain records of all visitors.

### 4.2: Surveillance and Monitoring

**Action**: Install surveillance systems to monitor physical premises.

- **Benefits**:
  - Deters unauthorized access.
  - Provides evidence in case of security incidents.

**Implementation**:

- **CCTV Cameras**: Place in strategic locations.
- **Motion Detectors**: Alert security personnel of movement in restricted areas.
- **Alarm Systems**: Trigger alarms upon unauthorized access.

---

## Step 5: Implement Hardware-Based Security Modules

### 5.1: Trusted Platform Module (TPM)

**Action**: Utilize TPM to enhance hardware security.

- **Benefits**:
  - Provides hardware-based cryptographic functions.
  - Securely stores encryption keys.

**Implementation**:

- **Check for TPM**: Verify if your hardware includes a TPM chip.
- **Enable TPM in BIOS/UEFI**: Access settings to activate TPM.
- **Integrate with LUKS**:

  - Use TPM to store LUKS keys securely.
  - **Note**: Requires advanced configuration.

- **References**:

  - [Arch Linux TPM Encryption](https://wiki.archlinux.org/title/Trusted_Platform_Module)

### 5.2: Hardware Security Keys

**Action**: Use hardware security keys (e.g., YubiKey) for multi-factor authentication.

- **Benefits**:
  - Adds an additional layer of security for system logins and privileged actions.
  - Protects against unauthorized access even if passwords are compromised.

**Implementation**:

- **Purchase a Compatible Key**: Such as YubiKey or similar devices.
- **Configure PAM Modules**:

  - Install `pam_u2f`:

    ```bash
    sudo pacman -S pam_u2f
    ```

  - Register the key and configure `/etc/pam.d/system-auth`.

- **References**:

  - [Arch Linux U2F Authentication](https://wiki.archlinux.org/title/U2F)

---

## Step 6: Regular Maintenance and Audits

**Action**: Conduct regular physical security audits and maintain equipment.

- **Benefits**:
  - Identifies potential security gaps.
  - Ensures all security measures are functioning correctly.

**Implementation**:

- **Audit Checklist**:

  - Verify locks and access controls are operational.
  - Check surveillance equipment functionality.
  - Review access logs for anomalies.
  - Inspect hardware for signs of tampering.

- **Equipment Maintenance**:

  - Ensure hardware components are in good condition.
  - Replace failing components promptly.
  - Keep firmware and hardware security features up to date.

---

## References

- [Arch Linux Security Guide](https://wiki.archlinux.org/title/Security)
- [Physical Security in IT](https://www.sans.org/white-papers/physical-security-it/)
- [NIST Physical Security Standards](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-116.pdf)
- [Trusted Platform Module](https://www.trustedcomputinggroup.org/tpm-main-specification/)
- [Hardware Security Modules](https://en.wikipedia.org/wiki/Hardware_security_module)

---

By implementing the measures outlined in this guide, you significantly enhance the physical security of your Arch Linux system. Remember that physical security is an ongoing process that requires regular evaluation and updates to address new threats and vulnerabilities.

