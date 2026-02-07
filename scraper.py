import re
from collections import Counter, defaultdict
from urllib.parse import urlparse, urldefrag, urljoin
import atexit
from bs4 import BeautifulSoup

ALLOWED_DOMAINS = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)
UNIQUE_URLS = set()                 # defragmented URLs
WORD_FREQ = Counter()               # all words across crawl (minus stopwords)
SUBDOMAIN_PAGES = defaultdict(set)  # subdomain -> set(defragmented urls)
LONGEST_PAGE_URL = None
LONGEST_PAGE_WORDS = 0
def dump_final_report():
    # Print to terminal (so you can copy into your report)
    print("\n" + "="*40)
    print("FINAL CRAWL ANALYTICS")
    print("="*40)
    print("Unique pages:", len(UNIQUE_URLS))
    print("Longest page:", LONGEST_PAGE_URL)
    print("Longest page word count:", LONGEST_PAGE_WORDS)

    print("\nTop 50 words (stopwords removed):")
    for w, c in WORD_FREQ.most_common(50):
        print(f"{w}\t{c}")

    print("\nSubdomains (alphabetical) with unique page counts:")
    for sub in sorted(SUBDOMAIN_PAGES.keys()):
        print(f"{sub}, {len(SUBDOMAIN_PAGES[sub])}")

    # Also write to ONE file for safety
    with open("final_report_stats.txt", "w", encoding="utf-8") as f:
        f.write("Unique pages: " + str(len(UNIQUE_URLS)) + "\n")
        f.write("Longest page: " + str(LONGEST_PAGE_URL) + "\n")
        f.write("Longest page word count: " + str(LONGEST_PAGE_WORDS) + "\n\n")

        f.write("Top 50 words (stopwords removed):\n")
        for w, c in WORD_FREQ.most_common(50):
            f.write(f"{w}\t{c}\n")

        f.write("\nSubdomains (alphabetical) with unique page counts:\n")
        for sub in sorted(SUBDOMAIN_PAGES.keys()):
            f.write(f"{sub}, {len(SUBDOMAIN_PAGES[sub])}\n")
atexit.register(dump_final_report)

def load_stopwords(path="stopwords.txt"):
    sw = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if not line:
                    continue

                # some lines contain multiple words
                for chunk in line.split():
                    for tok in tokenize_text(chunk):
                        if len(tok) >= 2:
                            sw.add(tok)

    except FileNotFoundError:
        print("WARNING: stopwords.txt not found — stopword removal disabled.")

    return sw



def tokenize_text(text: str):
    tokens = []
    current = []

    for ch in text:
        if ch.isalnum():
            current.append(ch.lower())
        else:
            if current:
                token = "".join(current)
                # skip tokens that are only digits
                if any(c.isalpha() for c in token):
                    tokens.append(token)
                current = []
    if current:
        token = "".join(current)
        if any(c.isalpha() for c in token):
            tokens.append(token)

    return tokens

STOPWORDS = load_stopwords()
JUNK = {
    "html",
    "update",
    "automatic",
    "markdown",
    "rmd",
    "git",
    "file",
    "files",
    "store",
    "ds",
}

def extract_visible_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")

    # remove non-content tags everywhere
    for tag in soup(["script", "style", "noscript", "svg", "iframe", "form", "meta", "link"]):
        tag.decompose()

    # Try to focus on main content area only
    main = None
    for selector in [
        "main",
        "article",
        "#content",
        "#main",
        ".content",
        ".entry-content",
        ".post-content",
        ".page-content",
        ".site-content",
    ]:
        main = soup.select_one(selector)
        if main:
            break

    # Fallback: body
    if not main:
        main = soup.body or soup

    # Remove obvious boilerplate within the chosen container
    for tag in main.find_all(["header", "footer", "nav", "aside"]):
        tag.decompose()

    # Remove containers commonly used for menus/sidebars/breadcrumbs/cookie banners
    for node in main.find_all(attrs={"class": re.compile(r"(menu|nav|footer|header|sidebar|breadcrumb|cookie|popup)", re.I)}):
        node.decompose()
    for node in main.find_all(attrs={"id": re.compile(r"(menu|nav|footer|header|sidebar|breadcrumb|cookie|popup)", re.I)}):
        node.decompose()

    text = main.get_text(separator=" ")
    text = re.sub(r"\s+", " ", text).strip()
    return text



def scraper(url, resp):
    global LONGEST_PAGE_URL, LONGEST_PAGE_WORDS

    links = extract_next_links(url, resp)
        # Only run analytics on real HTML pages
    content_type = ""
    try:
        content_type = (resp.raw_response.headers.get("Content-Type") or "").lower()
    except Exception:
        content_type = ""

    if "text/html" not in content_type:
        return [link for link in links if is_valid(link)]


    # ------------ Analytics collection ------------
    if resp is not None and getattr(resp, "status", None) == 200 and getattr(resp, "raw_response", None) is not None:
        content = getattr(resp.raw_response, "content", None)
        if content:
            try:
                html = content.decode("utf-8", errors="ignore")
                text = extract_visible_text(html)
                tokens = tokenize_text(text)
                                
                if len(tokens) < 50:
                    return [link for link in links if is_valid(link)]

                # Defragment the page URL for uniqueness definition
                page_url = getattr(resp, "url", url) or url
                page_url, _ = urldefrag(page_url)

                # Unique pages (URL-based)
                UNIQUE_URLS.add(page_url)
                

                # Subdomains in uci.edu
                parsed = urlparse(page_url)
                host = (parsed.hostname or "").lower()
                if host.endswith("uci.edu"):
                    SUBDOMAIN_PAGES[host].add(page_url)

                # Longest page by number of words (tokens)
                wc = len(tokens)
                if wc > LONGEST_PAGE_WORDS:
                    LONGEST_PAGE_WORDS = wc
                    LONGEST_PAGE_URL = page_url

                # Global word frequency (ignore stopwords)
                page_counts = Counter()
                for t in tokens:
                    if len(t) < 2 or len(t) > 30:
                        continue
                    if t in STOPWORDS or t in JUNK:
                        continue
                    page_counts[t] += 1

                CAP = 10
                for w, c in page_counts.items():
                    WORD_FREQ[w] += min(c, CAP)



            except Exception:
                pass
    # ---------------------------------------------

    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    links = []

    # Basic safety checks
    if resp is None or getattr(resp, "raw_response", None) is None:
        return links

    if getattr(resp, "status", None) != 200:
        return links

    content = getattr(resp.raw_response, "content", None)
    if not content:
        return links

    # Decode bytes -> string
    try:
        html = content.decode("utf-8", errors="ignore")
    except Exception:
        return links

    # Find href="..." or href='...'
    for match in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        href = match.group(1).strip()
        if not href:
            continue

        # Skip non-web links
        lower = href.lower()
        if lower.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue

        # Make absolute
        absolute = urljoin(resp.url if hasattr(resp, "url") and resp.url else url, href)

        # Defragment
        absolute, _ = urldefrag(absolute)

        links.append(absolute)

    return links


def is_valid(url):
    try:
        if not url:
            return False

        # STEP 1a: remove fragment (#...)
        url, _ = urldefrag(url)

        parsed = urlparse(url)
        q = (parsed.query or "").lower()
        if "replytocom=" in q or "share=" in q:
            return False
        if "oembed" in q or "format=xml" in q:
            return False

        path = parsed.path.lower()
        if path.endswith("/feed") or "/feed/" in path or path.endswith(".xml"):
            return False

        # STEP 1b: scheme check
        if parsed.scheme not in {"http", "https"}:
            return False

        # STEP 1c: domain restriction
        host = (parsed.hostname or "").lower()
        if not any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS):
            return False
        bad_paths = [
            "/wp-json/",
            "/wp-content/uploads/",
        ]
        if any(bad in parsed.path.lower() for bad in bad_paths):
            return False

        # STEP 1d: file-extension blacklist (your original)
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            parsed.path.lower()
        ):
            return False

        return True

    except TypeError:
        return False


