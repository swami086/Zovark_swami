# Zovark VM Appliance Builder
# Builds Ubuntu 24.04 VM with Docker, Zovark, and pre-pulled models
# Output: QCOW2 (KVM/Proxmox) + VMDK (VMware)
#
# Requirements: Packer 1.9+, QEMU/KVM, 30GB disk space
# Build: packer build zovark-appliance.pkr.hcl

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
  }
}

variable "zovark_version" {
  type    = string
  default = "2.0.0"
}

variable "ubuntu_iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/24.04/ubuntu-24.04.2-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  type    = string
  default = "sha256:TO_BE_UPDATED"
}

source "qemu" "zovark" {
  iso_url          = var.ubuntu_iso_url
  iso_checksum     = var.ubuntu_iso_checksum
  output_directory = "output-zovark-${var.zovark_version}"
  vm_name          = "zovark-${var.zovark_version}.qcow2"

  disk_size    = "30G"
  memory       = 4096
  cpus         = 2

  format      = "qcow2"
  accelerator = "kvm"

  ssh_username     = "zovark"
  ssh_password     = "zovark-install"
  ssh_timeout      = "30m"

  boot_wait = "5s"
  boot_command = [
    "<esc><wait>",
    "linux /casper/vmlinuz --- autoinstall ds=\"nocloud\"<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  http_directory    = "http"
  shutdown_command  = "sudo shutdown -P now"
}

build {
  sources = ["source.qemu.zovark"]

  # Install Docker
  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y ca-certificates curl gnupg lsb-release",
      "sudo install -m 0755 -d /etc/apt/keyrings",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
      "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" | sudo tee /etc/apt/sources.list.d/docker.list",
      "sudo apt-get update",
      "sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin",
      "sudo usermod -aG docker zovark",
      "sudo systemctl enable docker",
    ]
  }

  # Install NVIDIA Container Toolkit (optional — for GPU support)
  provisioner "shell" {
    inline = [
      "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg",
      "curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list",
      "sudo apt-get update",
      "sudo apt-get install -y nvidia-container-toolkit || true",
      "sudo nvidia-ctk runtime configure --runtime=docker || true",
    ]
  }

  # Copy Zovark files
  provisioner "file" {
    source      = "../"
    destination = "/opt/zovark/"
  }

  # Setup Zovark
  provisioner "shell" {
    inline = [
      "cd /opt/zovark",
      "sudo docker compose pull 2>&1 | tail -5",
      "sudo chmod +x scripts/deploy.sh scripts/hardware_check.sh",

      # Create first-boot systemd service
      "sudo tee /etc/systemd/system/zovark-firstboot.service > /dev/null <<'SERVICE'",
      "[Unit]",
      "Description=Zovark First Boot Setup",
      "After=docker.service",
      "ConditionPathExists=!/opt/zovark/.deployed",
      "",
      "[Service]",
      "Type=oneshot",
      "ExecStart=/opt/zovark/scripts/firstboot.sh",
      "RemainAfterExit=yes",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "SERVICE",
      "sudo systemctl enable zovark-firstboot",
    ]
  }

  # Create first-boot script
  provisioner "shell" {
    inline = [
      "sudo tee /opt/zovark/scripts/firstboot.sh > /dev/null <<'FBSCRIPT'",
      "#!/bin/bash",
      "echo '═══════════════════════════════════════'",
      "echo '  ZOVARK FIRST BOOT SETUP'",
      "echo '═══════════════════════════════════════'",
      "cd /opt/zovark",
      "export ZOVARK_MODE=templates-only",
      "docker compose up -d 2>&1",
      "sleep 30",
      "echo 'Zovark is running!'",
      "echo \"Dashboard: http://$(hostname -I | awk '{print $1}'):3000\"",
      "touch /opt/zovark/.deployed",
      "FBSCRIPT",
      "sudo chmod +x /opt/zovark/scripts/firstboot.sh",
    ]
  }

  # Convert to VMDK for VMware
  post-processor "shell-local" {
    inline = [
      "echo 'Converting QCOW2 to VMDK...'",
      "qemu-img convert -f qcow2 -O vmdk output-zovark-${var.zovark_version}/zovark-${var.zovark_version}.qcow2 output-zovark-${var.zovark_version}/zovark-${var.zovark_version}.vmdk || echo 'VMDK conversion skipped (install qemu-img)'",
      "echo ''",
      "echo 'Outputs:'",
      "echo '  QCOW2: output-zovark-${var.zovark_version}/zovark-${var.zovark_version}.qcow2'",
      "echo '  VMDK:  output-zovark-${var.zovark_version}/zovark-${var.zovark_version}.vmdk'",
    ]
  }
}
