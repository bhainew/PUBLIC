#!/bin/bash

echo "==============================="
echo "⚡ FLASH BOT AUTO SETUP START ⚡"
echo "==============================="

# -------------------------------
# Update system
# -------------------------------
echo "📦 Updating system packages..."
apt update -y && apt upgrade -y

# -------------------------------
# Install system dependencies
# -------------------------------
echo "🧰 Installing required system libraries..."
apt install -y python3 python3-pip python3-venv git curl wget unzip \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxrandr2 libgbm1 libgtk-3-0 \
    libasound2 libpangocairo-1.0-0 libpango-1.0-0 libcairo2 \
    libdrm2 libxfixes3 libx11-xcb1 libxcb1 libxext6 libx11-6

# -------------------------------
# Create virtual environment (recommended)
# -------------------------------
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

echo "🔁 Activating virtual environment..."
source venv/bin/activate

# -------------------------------
# Upgrade pip
# -------------------------------
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# -------------------------------
# Install Python dependencies
# -------------------------------
echo "📚 Installing Python libraries..."

# Required libraries from your requirements.txt
pip install playwright
pip install playwright-stealth==1.0.6
pip install instagrapi==2.0.0
pip install python-telegram-bot==20.7
pip install psutil
pip install typing-extensions
pip install urllib3
pip install requests
pip install asyncio
pip install cryptography
pip install unicodedata2
pip install Pillow

# Fix stealth conflict (important for your bot)
pip uninstall playwright_stealth -y || true
pip install playwright-stealth==1.0.6

# -------------------------------
# Install Playwright browsers
# -------------------------------
echo "🌐 Installing Playwright Chromium..."
playwright install chromium

echo "📦 Installing Playwright dependencies..."
playwright install-deps

# -------------------------------
# Create required folders
# -------------------------------
echo "📁 Creating project folders..."
mkdir -p sessions
mkdir -p logs

# -------------------------------
# Permissions
# -------------------------------
chmod +x *.py

# -------------------------------
# Done
# -------------------------------
echo ""
echo "======================================="
echo "✅ SETUP COMPLETED SUCCESSFULLY!"
echo "======================================="
echo ""
echo "To run your bot use:"
echo ""
echo "source venv/bin/activate"
echo "python3 1.py"
echo ""
echo "🔥 Your Flash Bot is ready!"
echo "======================================="