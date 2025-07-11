#!/bin/bash

# Maull-Script V1.5 Quick Installer
# Run this script to start the installation

clear
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Maull-Script V1.5                        ║"
echo "║              Advanced VPN/Tunnel Manager                    ║"
echo "║                     Quick Installer                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root"
    echo "Please run: sudo bash install.sh"
    exit 1
fi

echo "🚀 Starting Maull-Script V1.5 installation..."
echo "This will install and configure all necessary components"
echo ""

# Make the main script executable
chmod +x maull-script.sh

# Run the main installer
./maull-script.sh install

echo ""
echo "✅ Installation completed!"
echo ""
echo "📋 Next steps:"
echo "1. Run: bash maull-script.sh menu"
echo "2. Setup your domain in Domain & SSL Management"
echo "3. Create user accounts for your protocols"
echo ""
echo "📖 For help and documentation, check the README.md file"