"""
PhishGuard Development and Fallback Dataset Generator.
Contains labeled samples of phishing URLs, credential harvesting, investment scams,
recruitment scams, and benign communications for local testing and pipeline validation.
"""

from typing import List, Dict

DEVELOPMENT_DATASET: List[Dict[str, str]] = [
    # Phishing & Credential Theft
    {
        "text": "URGENT: Your PayPal account has been suspended due to unauthorized access. Verify your identity immediately at http://paypal.com.verify-user-security.xyz or account will be permanently locked within 24 hours.",
        "label": "phishing"
    },
    {
        "text": "Bank of America Security Alert: Unusual sign-in detected. Please enter your one-time password (OTP) and confirm your password at http://192.168.1.55/boa/login to restore access.",
        "label": "phishing"
    },
    {
        "text": "Apple Support: Your Apple ID was used to purchase an iPhone. If this was not you, call 1-800-555-0199 or click here to cancel transaction.",
        "label": "phishing"
    },
    {
        "text": "USPS: Your parcel delivery failed due to unpaid customs fee of $2.30. Pay clearance fee within 12 hours at http://usps-tracking-package-update.top to prevent package return.",
        "label": "phishing"
    },
    {
        "text": "Dear user, immediate action required. Please share your verification code to prevent your mailbox from being terminated.",
        "label": "phishing"
    },

    # Financial & Investment Scams
    {
        "text": "Guaranteed 300% returns in 48 hours! 100% risk-free crypto automated trading algorithm. Send 0.1 BTC to our mining pool and double your money daily. Contact @cryptoprofits on Telegram.",
        "label": "phishing"
    },
    {
        "text": "Congratulations you have won $1,000,000 in the International Unclaimed Funds Lottery. To claim your prize, please wire the $450 processing fee via Western Union.",
        "label": "phishing"
    },

    # Fake Recruitment
    {
        "text": "Amazon Remote Assistant: Earn $400/day for simple rating tasks. No interview needed! Instant hiring. Contact our HR manager immediately on WhatsApp at +123456789.",
        "label": "phishing"
    },
    {
        "text": "Congratulations on your selection for Data Entry Specialist! You only need to purchase your home office equipment starter kit for $199 from our verified vendor.",
        "label": "phishing"
    },

    # Benign Communications
    {
        "text": "Hi Alex, hope you are having a productive week. Attached is the agenda for our project review meeting tomorrow at 2 PM. Let me know if you want to add any topics.",
        "label": "benign"
    },
    {
        "text": "Thanks for submitting the pull request! I reviewed the documentation changes and left two minor comments on GitHub. Great work.",
        "label": "benign"
    },
    {
        "text": "Dear team, the quarterly planning session is scheduled for Thursday morning in Conference Room B. Please review the attached slide deck in advance. Regards, Management.",
        "label": "benign"
    },
    {
        "text": "Hey Sarah, are you still free for lunch today at 12:30? Let me know if that time works or if you want to catch up later this afternoon.",
        "label": "benign"
    },
    {
        "text": "Your Amazon order #112-9839482 has shipped. Track your shipment at https://www.amazon.com/orders. Thank you for shopping with us.",
        "label": "benign"
    },
    {
        "text": "Here is the calendar invite for the weekly engineering synchronization call. Zoom link is attached. Sincerely, Engineering Operations.",
        "label": "benign"
    }
]

def get_development_dataset() -> List[Dict[str, str]]:
    return DEVELOPMENT_DATASET
