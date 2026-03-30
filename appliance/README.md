# Zovark VM Appliance

Pre-built Ubuntu 24.04 VM with Docker, Zovark, and all dependencies.
Deploy to VMware, KVM, Proxmox, or any hypervisor.

## Quick Start

1. Import the OVA/QCOW2 into your hypervisor
2. Boot the VM (allocate 16GB+ RAM, 4+ vCPU)
3. SSH in: `ssh zovark@<vm-ip>` (password: `zovark-install`)
4. Run: `sudo /opt/zovark/scripts/deploy.sh --siem splunk --admin your@email.com`
5. Open: `http://<vm-ip>:3000`

## For GPU Support

1. Pass through an NVIDIA GPU to the VM
2. Install NVIDIA drivers: `sudo apt install nvidia-driver-550`
3. Re-run deploy with: `--gpu nvidia`

## Building the Appliance

Requirements: Linux with Packer 1.9+, QEMU, KVM, 30GB disk

```bash
cd appliance
packer init zovark-appliance.pkr.hcl
packer build zovark-appliance.pkr.hcl
```

Outputs:
- `output-zovark-X.X.X/zovark-X.X.X.qcow2` — KVM/Proxmox
- `output-zovark-X.X.X/zovark-X.X.X.vmdk` — VMware (convert to OVA with ovftool)

## Deployment Modes

| Mode | GPU | Capacity | Price |
|------|-----|----------|-------|
| Templates-only | None | Template-matched alerts | $40K/yr |
| Full AI | NVIDIA A30+ | All alert types | $100K+/yr |
