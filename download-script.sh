#!/bin/bash

# Alternative download script for Maull-Script V1.5
# Use this if the main installer fails

clear
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                 Maull-Script V1.5 Downloader                ║"
echo "║              Alternative Installation Method                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root"
    echo "Please run: sudo bash download-script.sh"
    exit 1
fi

echo "🔄 Attempting to download Maull-Script from multiple sources..."

# Method 1: Try with curl
echo "📥 Trying download with curl..."
curl -L -o maull-script.sh "https://raw.githubusercontent.com/YOUR_USERNAME/maull-script/main/maull-script.sh" 2>/dev/null

# Method 2: Try with wget if curl failed
if [[ ! -f "maull-script.sh" || ! -s "maull-script.sh" ]]; then
    echo "📥 Trying download with wget..."
    wget -O maull-script.sh "https://raw.githubusercontent.com/YOUR_USERNAME/maull-script/main/maull-script.sh" 2>/dev/null
fi

# Method 3: Try master branch
if [[ ! -f "maull-script.sh" || ! -s "maull-script.sh" ]]; then
    echo "📥 Trying master branch..."
    wget -O maull-script.sh "https://raw.githubusercontent.com/YOUR_USERNAME/maull-script/master/maull-script.sh" 2>/dev/null
fi

# Method 4: Create script manually if all downloads fail
if [[ ! -f "maull-script.sh" || ! -s "maull-script.sh" ]]; then
    echo "⚠️  All download methods failed. Please:"
    echo "1. Check your GitHub repository URL"
    echo "2. Make sure the repository is public"
    echo "3. Verify the file exists in your repository"
    echo "4. Check your internet connection"
    echo ""
    echo "Manual installation steps:"
    echo "1. Go to your GitHub repository"
    echo "2. Copy the raw content of maull-script.sh"
    echo "3. Create the file manually: nano maull-script.sh"
    echo "4. Paste the content and save"
    echo "5. Run: chmod +x maull-script.sh"
    echo "6. Run: ./maull-script.sh install"
    exit 1
fi

# Make executable and run
chmod +x maull-script.sh

echo "✅ Download successful!"
echo "🚀 Starting installation..."

./maull-script.sh install

echo ""
echo "✅ Installation completed!"
echo "📋 Run: bash maull-script.sh menu"
