from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from html import unescape
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.services.knowledge import KnowledgeError, add_knowledge


class DocFetchError(RuntimeError):
    """Raised when documentation fetching is disabled or unsafe."""


@dataclass
class DocSearchResult:
    title: str
    url: str
    source: str
    official: bool


@dataclass
class FetchedDocument:
    url: str
    title: str
    text: str
    official: bool


@dataclass
class SavedFetchedDocument:
    document: FetchedDocument
    knowledge_id: int
    summarized: bool
    warning: str | None = None


OFFICIAL_VENDOR_DOMAINS = {
    "cisco": ("cisco.com",),
    "mikrotik": ("mikrotik.com", "help.mikrotik.com"),
    "ubiquiti": ("ui.com", "help.ui.com"),
    "juniper": ("juniper.net",),
    "aruba": ("arubanetworks.com", "hpe.com"),
    "hp": ("hpe.com",),
}


def search_official_docs(vendor: str, model: str) -> list[DocSearchResult]:
    _require_enabled()
    return []


def fetch_url_content(url: str, vendor: str | None = None) -> FetchedDocument:
    _require_enabled()
    safe_url = validate_public_http_url(url)
    official = _is_official_source(safe_url, vendor or "")
    if not official and not settings.doc_fetch_allow_non_official:
        raise DocFetchError(
            "URL does not look like an official vendor source. Set "
            "DOC_FETCH_ALLOW_NON_OFFICIAL=true to allow non-official sources explicitly."
        )

    try:
        with httpx.Client(
            timeout=settings.doc_fetch_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "NetworkAssistantDocs/1.0"},
        ) as client:
            response = client.get(safe_url)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise DocFetchError(f"Documentation fetch failed: {exc}") from exc

    final_url = validate_public_http_url(str(response.url))
    final_official = _is_official_source(final_url, vendor or "")
    if not final_official and not settings.doc_fetch_allow_non_official:
        raise DocFetchError("Final redirected URL is not an official vendor source.")
    text, title = _extract_text(response.text)
    if not text:
        raise DocFetchError("Fetched page did not contain readable text.")
    return FetchedDocument(
        url=final_url,
        title=title or final_url,
        text=text[:50000],
        official=final_official,
    )


def summarize_document_for_network_knowledge(
    document: FetchedDocument,
    vendor: str,
    model: str,
    doc_type: str,
) -> tuple[str, bool, str | None]:
    if not settings.llm_enabled or not settings.deepseek_api_key:
        return _fallback_summary(document, vendor, model, doc_type), False, (
            "DeepSeek is disabled or missing an API key; saved extracted text summary instead."
        )

    prompt = (
        "Summarize this vendor documentation for a local network technician. "
        "Do not invent facts. Do not suggest executing commands automatically. "
        "Output practical sections exactly like: Title, Vendor, Model, Source, Doc Type, "
        "Practical Notes, Connection / Access, Safe Read-Only Commands, Configuration Notes, "
        "Reset / Recovery, Warnings, Source URL.\n\n"
        f"Vendor: {vendor}\nModel: {model}\nDoc Type: {doc_type}\nSource URL: {document.url}\n"
        f"Document Title: {document.title}\n\nDocument Text:\n{document.text[:16000]}"
    )
    try:
        with httpx.Client(timeout=45) as client:
            response = client.post(
                f"{settings.deepseek_base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.deepseek_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.deepseek_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You summarize device documentation into concise local knowledge. "
                                "You cannot execute commands or browse further."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1200,
                },
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"].strip()
            if content:
                return content, True, None
    except Exception as exc:
        return _fallback_summary(document, vendor, model, doc_type), False, (
            f"DeepSeek summarization failed; saved extracted text summary instead: {exc}"
        )
    return _fallback_summary(document, vendor, model, doc_type), False, "DeepSeek returned an empty summary."


def save_fetched_document_as_knowledge(
    url: str,
    vendor: str,
    model: str | None,
    doc_type: str,
    trusted: bool,
    tags: str = "",
) -> SavedFetchedDocument:
    document = fetch_url_content(url, vendor=vendor)
    content, summarized, warning = summarize_document_for_network_knowledge(
        document=document,
        vendor=vendor,
        model=model or "",
        doc_type=doc_type,
    )
    try:
        item = add_knowledge(
            title=document.title[:255],
            content=content,
            vendor=vendor,
            model=model,
            doc_type=doc_type,
            tags=tags or ("fetched-docs, official" if document.official else "fetched-docs"),
            source_name=document.url,
            is_trusted=trusted,
            source_type="internet",
            source_url=document.url,
        )
    except KnowledgeError as exc:
        raise DocFetchError(str(exc)) from exc
    return SavedFetchedDocument(
        document=document,
        knowledge_id=item.id,
        summarized=summarized,
        warning=warning,
    )


def _require_enabled() -> None:
    if not settings.doc_fetch_enabled:
        raise DocFetchError(
            "Documentation fetching is disabled. Set DOC_FETCH_ENABLED=true in .env to use knowledge fetch commands."
        )


def validate_public_http_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise DocFetchError("Only http:// and https:// URLs are allowed.")
    if not parsed.hostname:
        raise DocFetchError("URL must include a hostname.")
    hostname = parsed.hostname.strip().lower()
    if hostname in {"localhost"} or hostname.endswith(".localhost") or "." not in hostname:
        raise DocFetchError("Local or internal hostnames are blocked.")
    try:
        ip = ipaddress.ip_address(hostname)
        _reject_private_ip(ip)
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise DocFetchError(f"Hostname did not resolve through public DNS: {hostname}") from exc
        for info in infos:
            _reject_private_ip(ipaddress.ip_address(info[4][0]))
    return url


def _validate_public_http_url(url: str) -> str:
    return validate_public_http_url(url)


def _reject_private_ip(ip: ipaddress._BaseAddress) -> None:
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise DocFetchError(f"Blocked unsafe documentation target address: {ip}")


def _is_official_source(url: str, vendor: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower()
    vendor_key = vendor.lower().strip()
    domains = OFFICIAL_VENDOR_DOMAINS.get(vendor_key, ())
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in domains)


def _extract_text(html: str) -> tuple[str, str]:
    try:
        from readability import Document

        doc = Document(html)
        title = unescape(doc.short_title() or "")
        summary_html = doc.summary(html_partial=True)
        text = _soup_text(summary_html)
        if text:
            return text, title
    except Exception:
        pass
    return _soup_text(html), _soup_title(html)


def _soup_text(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
    except ImportError as exc:
        raise DocFetchError("beautifulsoup4 is not installed. Run `pip install -r requirements.txt`.") from exc
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    lines = [line.strip() for line in soup.get_text("\n").splitlines()]
    return "\n".join(line for line in lines if line)


def _soup_title(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    return soup.title.string.strip() if soup.title and soup.title.string else ""


def _fallback_summary(document: FetchedDocument, vendor: str, model: str, doc_type: str) -> str:
    preview = document.text[:6000]
    return (
        f"Title: {document.title}\n"
        f"Vendor: {vendor}\n"
        f"Model: {model or '--'}\n"
        f"Source: {document.url}\n"
        f"Doc Type: {doc_type}\n\n"
        "Practical Notes:\n"
        f"{preview}\n\n"
        "Connection / Access:\n- Review the source document before using device-specific access methods.\n\n"
        "Safe Read-Only Commands:\n- Treat commands in this document as reference only; run commands manually through existing allowlisted CLI tools.\n\n"
        "Configuration Notes:\n- Fetched documentation is local knowledge, not permission to execute configuration.\n\n"
        "Reset / Recovery:\n- Review official source text above for reset or recovery procedures if present.\n\n"
        "Warnings:\n- Do not execute commands from fetched documentation automatically.\n\n"
        f"Source URL:\n{document.url}"
    )
