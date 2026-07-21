from __future__ import annotations
from typing import *
import re, json, logging, ast, math, hmac, hashlib, sqlite3, time, uuid, asyncio
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field, asdict


# LOGGER
# ===========================================================================

_LOGGER = logging.getLogger("llm_output_guard")
if not _LOGGER.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
    _LOGGER.addHandler(_h)
    _LOGGER.setLevel(logging.INFO)


# ===========================================================================
# HELPERS 
# ===========================================================================

def _calculate_risk_score(score: float, threshold: float) -> float:
    if score > threshold:
        risk = round((score - threshold) / (1.0 - threshold), 1)
    else:
        risk = round((score - threshold) / threshold, 1)
    return max(-1.0, min(1.0, risk))


class _TextReplaceBuilder:
    def __init__(self, original_text: str) -> None:
        self._text = original_text
        self._original = original_text

    @property
    def output_text(self) -> str:
        return self._text

    def get_text_in_position(self, start: int, end: int) -> str:
        return self._text[start:end]

    def replace_text_get_insertion_index(self, replacement: str, start: int, end: int) -> int:
        self._text = self._text[:start] + replacement + self._text[end:]
        return start + len(replacement)


# ===========================================================================
# PATTERN CONSTANTS 
# ===========================================================================

PII_PATTERNS: List[Dict[str, Any]] = [
    {"name": "CREDIT_CARD_RE", "expressions": [r"(?:(4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})|(3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5})|(3(?:0[0-5]|[68]\d)\d{11}))"], "score": 0.95},
    {"name": "UUID", "expressions": [r"[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}"], "score": 0.85},
    {"name": "EMAIL_ADDRESS_RE", "expressions": [r"\b[A-Za-z0-9._%+-]+(\[AT\]|@)[A-Za-z0-9.-]+(\[DOT\]|\.)[A-Za-z]{2,}\b"], "score": 0.95},
    {"name": "US_SSN_RE", "expressions": [r"\b\d{3}-\d{2}-\d{4}\b"], "score": 0.95},
    {"name": "BTC_ADDRESS", "expressions": [r"(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])"], "score": 0.85},
    {"name": "IP_ADDRESS", "expressions": [r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"], "score": 0.7},
    {"name": "IBAN_CODE", "expressions": [r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"], "score": 0.85},
    {"name": "PHONE_NUMBER", "expressions": [r"(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?)"], "score": 0.7},
    {"name": "URL", "expressions": [r"https?://[^\s<>\"']+", r"www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s<>\"']*)?"], "score": 0.4},
    {"name": "DATE_RE", "expressions": [r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b"], "score": 0.4},
]

SECRET_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("OpenAI API Key", re.compile(r"\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b")),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b")),
    ("GitHub Fine-grained PAT", re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20}\b")),
    ("Slack Bot Token", re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b")),
    ("Slack User Token", re.compile(r"\bxox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}\b")),
    ("Slack Webhook", re.compile(r"https?://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/]{43,46}")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key (ctx)", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\\-_]{35}\b")),
    ("Google OAuth Access", re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b")),
    ("Stripe Key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b")),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Square OAuth Secret", re.compile(r"\bsq0csp-[0-9A-Za-z_\-]{43}\b")),
    ("Square Access Token", re.compile(r"\bsq0atp-[0-9A-Za-z_\-]{22}\b")),
    ("Heroku API Key (ctx)", re.compile(r"(?i)heroku[^\n]{0,40}[:=][ ]*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?")),
    ("HuggingFace Token", re.compile(r"\bhf_[a-zA-Z]{34}\b")),
    ("HuggingFace Org Token", re.compile(r"\bapi_org_[a-zA-Z]{34}\b")),
    ("Discord Bot Token", re.compile(r"\b[NzM][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}\b")),
    ("Telegram Bot Token", re.compile(r"\b[0-9]{5,16}:A[a-zA-Z0-9_\-]{34}\b")),
    ("Twitter Bearer (ctx)", re.compile(r"(?i)twitter[^\n]{0,40}[:=][ ]*[\"']?(A{22}[a-zA-Z0-9%]{80,100})[\"']?")),
    ("Twitter Access Token", re.compile(r"(?i)twitter[^\n]{0,40}[:=][ ]*[\"']?([0-9]{15,25}-[a-zA-Z0-9]{20,40})[\"']?")),
    ("LinkedIn Secret (ctx)", re.compile(r"(?i)linkedin[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{16})[\"']?")),
    ("SendGrid API Token", re.compile(r"\bSG\.[a-z0-9=_\-\.]{66}\b")),
    ("Mailgun Private Key", re.compile(r"\bkey-[a-f0-9]{32}\b")),
    ("Mailchimp Key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("JWT Token", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
    ("Slack App-level Token", re.compile(r"\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b")),
    ("Shopify Token", re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    ("Twitch API Token (ctx)", re.compile(r"(?i)twitch[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{30})[\"']?")),
    ("Authress Access Key", re.compile(r"\b(?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}\b")),
    ("Bitbucket PAT", re.compile(r"(?i)bitbucket[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{64})[\"']?")),
    ("JFrog Identity (ctx)", re.compile(r"(?i)(?:jfrog|artifactory)[^\n]{0,40}[:=][ ]*[\"']?([a-zA-Z0-9]{64})[\"']?")),
    ("Vault Service Token", re.compile(r"\bhvs\.[a-z0-9_-]{90,100}\b")),
    ("Vault Batch Token", re.compile(r"\bhvb\.[a-z0-9_-]{138,212}\b")),
    ("Yandex API Key (ctx)", re.compile(r"(?i)yandex[^\n]{0,40}[:=][ ]*[\"']?(AQVN[A-Za-z0-9_\-]{35,38})[\"']?")),
    ("Adafruit API Key (ctx)", re.compile(r"(?i)adafruit[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9_-]{32})[\"']?")),
    ("Adobe Client ID (ctx)", re.compile(r"(?i)adobe[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{32})[\"']?")),
    ("Adobe Client Secret", re.compile(r"\b(p8e-)[a-z0-9]{32}\b")),
    ("Age Secret Key", re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b")),
    ("Airtable Key (ctx)", re.compile(r"(?i)airtable[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{17})[\"']?")),
    ("Algolia Key", re.compile(r"\b(LTAI)[a-z0-9]{20}\b")),
    ("Alibaba AccessKey ID", re.compile(r"\bLTAI[a-z0-9]{20}\b")),
    ("Asana Secret (ctx)", re.compile(r"(?i)asana[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{32})[\"']?")),
    ("Atlassian Token (ctx)", re.compile(r"(?i)(?:atlassian|confluence|jira)[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{24})[\"']?")),
    ("Beamer Token (ctx)", re.compile(r"(?i)beamer[^\n]{0,40}[:=][ ]*[\"']?(b_[a-z0-9=_\-]{44})[\"']?")),
    ("Bittrex Key (ctx)", re.compile(r"(?i)bittrex[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{32})[\"']?")),
    ("Clojars Token", re.compile(r"\bCLOJARS_[a-z0-9]{60}\b")),
    ("Codecov Token (ctx)", re.compile(r"(?i)codecov[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{32})[\"']?")),
    ("Coinbase Token (ctx)", re.compile(r"(?i)coinbase[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9_-]{64})[\"']?")),
    ("Confluent Token (ctx)", re.compile(r"(?i)confluent[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{16})[\"']?")),
    ("Contentful Token (ctx)", re.compile(r"(?i)contentful[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{43})[\"']?")),
    ("Databricks Token", re.compile(r"\bdapi[a-h0-9]{32}\b")),
    ("Datadog Token (ctx)", re.compile(r"(?i)datadog[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{40})[\"']?")),
    ("DigitalOcean PAT", re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    ("Doppler Token", re.compile(r"\bdp\.pt\.[a-z0-9]{43}\b")),
    ("Duffel Token", re.compile(r"\bduffel_(?:test|live)_[a-z0-9_\-=]{43}\b")),
    ("Dynatrace Token", re.compile(r"\bdt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}\b")),
    ("Etsy Token (ctx)", re.compile(r"(?i)etsy[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{24})[\"']?")),
    ("Facebook Token (ctx)", re.compile(r"(?i)facebook[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{32})[\"']?")),
    ("Fastly Token (ctx)", re.compile(r"(?i)fastly[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{32})[\"']?")),
    ("Finicity Token (ctx)", re.compile(r"(?i)finicity[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{32})[\"']?")),
    ("Finnhub Token (ctx)", re.compile(r"(?i)finnhub[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{20})[\"']?")),
    ("Flickr Token (ctx)", re.compile(r"(?i)flickr[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{32})[\"']?")),
    ("Flutterwave Key", re.compile(r"\bFLW(?:SECK|PUBK)_TEST-[a-h0-9]{12,32}(?:-X)?\b")),
    ("Frame.io Token", re.compile(r"\bfio-u-[a-z0-9\-_=]{64}\b")),
    ("Freshbooks Token (ctx)", re.compile(r"(?i)freshbooks[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{64})[\"']?")),
    ("GoCardless Token", re.compile(r"\blive_[a-z0-9\-_=]{40}\b")),
    ("Grafana API key", re.compile(r"\beyJrIjoi[A-Za-z0-9]{70,400}={0,2}\b")),
    ("Grafana Cloud token", re.compile(r"\bglc_[A-Za-z0-9+/]{32,400}={0,2}\b")),
    ("Grafana Service token", re.compile(r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b")),
    ("HashiCorp TF Token", re.compile(r"\b[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}\b")),
    ("HubSpot Token (ctx)", re.compile(r"(?i)hubspot[^\n]{0,40}[:=][ ]*[\"']?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})[\"']?")),
    ("Intercom Token (ctx)", re.compile(r"(?i)intercom[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{60})[\"']?")),
    ("Kucoin Token (ctx)", re.compile(r"(?i)kucoin[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{24})[\"']?")),
    ("Launchdarkly Token (ctx)", re.compile(r"(?i)launchdarkly[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{40})[\"']?")),
    ("Linear API Token", re.compile(r"\blin_api_[a-z0-9]{40}\b")),
    ("Lob Token (ctx)", re.compile(r"(?i)lob[^\n]{0,40}[:=][ ]*[\"']?((?:live|test)_pub_[a-f0-9]{31})[\"']?")),
    ("Mailgun PubKey", re.compile(r"\bpubkey-[a-f0-9]{32}\b")),
    ("MapBox Token (ctx)", re.compile(r"(?i)mapbox[^\n]{0,40}[:=][ ]*[\"']?(pk\.[a-z0-9]{60}\.[a-z0-9]{22})[\"']?")),
    ("Mattermost Token (ctx)", re.compile(r"(?i)mattermost[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{26})[\"']?")),
    ("MessageBird Token (ctx)", re.compile(r"(?i)messagebird[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{25})[\"']?")),
    ("MS Teams Webhook", re.compile(r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9\-]+/IncomingWebhook/[a-z0-9]{32}/[a-z0-9\-]+")),
    ("Netlify Token (ctx)", re.compile(r"(?i)netlify[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{40,46})[\"']?")),
    ("NewRelic User Key", re.compile(r"\bNRAK-[a-z0-9]{27}\b")),
    ("NewRelic Browser Token", re.compile(r"\bNRJS-[a-f0-9]{19}\b")),
    ("NYTimes Token (ctx)", re.compile(r"(?i)nytimes[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{32})[\"']?")),
    ("Okta Token (ctx)", re.compile(r"(?i)okta[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9=_\-]{42})[\"']?")),
    ("PlanetScale Token", re.compile(r"\bpscale_(?:tkn|oauth|pw)_[a-z0-9=\-_\.]{32,64}\b")),
    ("Postman Token", re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b")),
    ("Prefect Token", re.compile(r"\bpnu_[a-z0-9]{36}\b")),
    ("Pulumi Token", re.compile(r"\bpul-[a-f0-9]{40}\b")),
    ("PyPI Upload Token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}\b")),
    ("RapidAPI Token (ctx)", re.compile(r"(?i)rapidapi[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9_-]{50})[\"']?")),
    ("Readme Token", re.compile(r"\brdme_[a-z0-9]{70}\b")),
    ("Rubygems Token", re.compile(r"\brubygems_[a-f0-9]{48}\b")),
    ("Scalingo Token", re.compile(r"\btk-us-[a-zA-Z0-9-_]{48}\b")),
    ("Sendbird Token (ctx)", re.compile(r"(?i)sendbird[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{40})[\"']?")),
    ("SendinBlue Token", re.compile(r"\bxkeysib-[a-f0-9]{64}-[a-z0-9]{16}\b")),
    ("Sentry Token (ctx)", re.compile(r"(?i)sentry[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{64})[\"']?")),
    ("Shippo Token", re.compile(r"\bshippo_(?:live|test)_[a-f0-9]{40}\b")),
    ("Sidekiq Secret (ctx)", re.compile(r"(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)[^\n]{0,40}[:=][ ]*[\"']?([a-f0-9]{8}:[a-f0-9]{8})[\"']?")),
    ("Snyk Token (ctx)", re.compile(r"(?i)snyk[^\n]{0,40}[:=][ ]*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?")),
    ("Squarespace Token (ctx)", re.compile(r"(?i)squarespace[^\n]{0,40}[:=][ ]*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?")),
    ("SumoLogic ID (ctx)", re.compile(r"(?i)sumo[^\n]{0,40}[:=][ ]*[\"']?(su[a-zA-Z0-9]{12})[\"']?")),
    ("TravisCI Token (ctx)", re.compile(r"(?i)travis[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{22})[\"']?")),
    ("Twitch Token (ctx)", re.compile(r"(?i)twitch[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{30})[\"']?")),
    ("Typeform Token (ctx)", re.compile(r"(?i)typeform[^\n]{0,40}[:=][ ]*[\"']?(tfp_[a-z0-9\-_\.=]{59})[\"']?")),
    ("Yandex Token (ctx)", re.compile(r"(?i)yandex[^\n]{0,40}[:=][ ]*[\"']?(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})[\"']?")),
    ("Zendesk Key (ctx)", re.compile(r"(?i)zendesk[^\n]{0,40}[:=][ ]*[\"']?([a-z0-9]{40})[\"']?")),
    ("Generic Bearer Token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b")),
    ("Generic Authorization", re.compile(r"(?i)(?:authorization|auth|token|api[_-]?key|secret|password|passwd|pwd)\s*[:=]\s*[\"']([A-Za-z0-9_\-\.+/=]{16,})[\"']")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
]

DEFAULT_BANNED_SUBSTRINGS: List[str] = [
    "[DAN]", "DAN:", "DAN Mode enabled", "ANTI-DAN:",
    "[🔓JAILBREAK]", "successfully jailbroken", "STAN:", "DUDE:",
    "(🔓Developer Mode Output)", "![http",
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X",
    "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTPHISH-STANDARD-ANTI-PHISH-TEST-EMAIL*C.34X",
]

DEFAULT_REFUSAL_PHRASES: List[str] = [
    "I'm sorry", "Sorry", "I am sorry", "I apologize", "As an", "As an AI",
    "I'm an", "I'm just", "As a language model", "As an Assistant", "I cannot",
    "I do not", "Hello!", "is illegal and unethical", "I'm really sorry",
    "OpenAI", "unethical", "not ethical", "not legal", "My apologies",
    "but I cannot", "If you have any other non-malicious requests",
    "I'm not able to provide", "I am really sorry", "I cannot create",
    "I cannot support", "I can't provide", "I can't assist",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "work", "gq", "tk", "ml",
    "cf", "ga", "cc", "country", "stream", "online", "site", "icu", "buzz",
    "cyou", "rest", "monster", "sbs", "skin", "fit", "bond", "autos", "rsvp",
}


