# VirusTotal Integration Setup

## Overview
BitSentinel now includes VirusTotal integration for enhanced threat intelligence. When you click on any IP in the Live Threat Feed, you'll see detailed information including VirusTotal data.

## Setup Instructions

### 1. Get VirusTotal API Key
1. Sign up for a free account at [https://www.virustotal.com](https://www.virustotal.com)
2. Go to your profile settings → API Key
3. Copy your API key

### 2. Configure Environment Variable
**Windows (Command Prompt):**
```cmd
set VIRUSTOTAL_API_KEY=your_api_key_here
```

**Windows (PowerShell):**
```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
```

**Permanent Environment Variable:**
1. Right-click "This PC" → Properties → Advanced system settings
2. Click "Environment Variables"
3. Add new variable:
   - Name: `VIRUSTOTAL_API_KEY`
   - Value: `your_api_key_here`

### 3. Restart the Application
```bash
python app.py
```

## Features

### Without API Key (Default)
- Shows "VirusTotal API key not configured" message
- Provides direct link to check IP on VirusTotal website
- All other features work normally

### With API Key
- **Reputation Score**: VirusTotal's reputation score (-100 to +100)
- **Country**: Geographic location of the IP
- **Malicious Count**: Number of malicious detections
- **Suspicious Count**: Number of suspicious detections
- **ASN Information**: Autonomous System details
- **Direct Link**: Quick access to full VirusTotal report

## Usage
1. Access the dashboard at `http://127.0.0.1:5000`
2. Click on any IP in the Live Threat Feed or blocked IPs list
3. View the IP detail modal with VirusTotal integration

## API Limits
- Free tier: 4 requests per minute, 1,000 requests per day
- Premium tier: Higher limits available
- The system gracefully handles rate limits and API errors

## Troubleshooting
- **API Key Not Working**: Verify the key is correct and not expired
- **Rate Limit Exceeded**: Upgrade to premium tier or wait for limit reset
- **Network Issues**: Check internet connectivity and firewall settings

## Privacy Note
- IP addresses are sent to VirusTotal for analysis
- No other sensitive data is shared
- Consider your organization's privacy policies
