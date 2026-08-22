function FindProxyForURL(url, host) {
    if (!host) return "DIRECT";
    host = host.toLowerCase();

    // GCS uploads: DIRECT + zapret DPI-desync (Tor exits are geo-blocked by Google).
    // Do NOT send storage.googleapis.com through Tor.

    // Sites that need Tor SOCKS (ISP DPI). Discord app + GCS stay DIRECT.
    if (
        host === "t.me" || dnsDomainIs(host, ".t.me") ||
        host === "telegram.org" || dnsDomainIs(host, ".telegram.org") ||
        host === "telegram.me" || dnsDomainIs(host, ".telegram.me") ||
        host === "telegram.dog" || dnsDomainIs(host, ".telegram.dog") ||
        host === "telegram-cdn.org" || dnsDomainIs(host, ".telegram-cdn.org") ||
        host === "cdn-telegram.org" || dnsDomainIs(host, ".cdn-telegram.org") ||
        host === "telegra.ph" || dnsDomainIs(host, ".telegra.ph") ||
        host === "graph.org" || dnsDomainIs(host, ".graph.org") ||
        host === "tg.dev" || dnsDomainIs(host, ".tg.dev") ||
        host === "telesco.pe" || dnsDomainIs(host, ".telesco.pe") ||
        shExpMatch(host, "*telegram*") ||
        host === "lospec.com" || dnsDomainIs(host, ".lospec.com") ||
        host === "pixelschool.org" || dnsDomainIs(host, ".pixelschool.org") ||
        host === "digitaloceanspaces.com" || dnsDomainIs(host, ".digitaloceanspaces.com") ||
        host === "x.com" || dnsDomainIs(host, ".x.com") ||
        host === "twitter.com" || dnsDomainIs(host, ".twitter.com") ||
        host === "t.co" || dnsDomainIs(host, ".t.co") ||
        host === "twimg.com" || dnsDomainIs(host, ".twimg.com") ||
        host === "pscp.tv" || dnsDomainIs(host, ".pscp.tv")
    ) {
        return "SOCKS5 127.0.0.1:9050";
    }

    // Microtask / AI crowdsourcing: Azure/CF geo-block DIRECT from RU.
    // Mindrift/Toloka work via Tor; Clickworker needs browser CF challenge (Tor better than hard RU block).
    // Use tor-us :9052 (US/DE/GB/SE/FR) for cleaner CF exits.
    if (
        host === "mindrift.toloka.ai" || dnsDomainIs(host, ".mindrift.toloka.ai") ||
        host === "toloka.ai" || dnsDomainIs(host, ".toloka.ai") ||
        host === "toloka.dev" || dnsDomainIs(host, ".toloka.dev") ||
        host === "toloka-test.ai" || dnsDomainIs(host, ".toloka-test.ai") ||
        host === "tlkfrontprod.azureedge.net" || dnsDomainIs(host, ".tlkfrontprod.azureedge.net") ||
        host === "prodtlkappspresetsfiles-cdn.azureedge.net" ||
        host === "prodtlkappspresetsfiles.blob.core.windows.net" ||
        host === "mindrift.zendesk.com" ||
        host === "tolokahelp.zendesk.com" ||
        host === "clickworker.com" || dnsDomainIs(host, ".clickworker.com")
    ) {
        return "SOCKS5 127.0.0.1:9052";
    }

    // YouTube + YouTube Music → tor-us :9052 (US/DE/GB/SE/FR).
    // System Tor :9050 is ExitNodes={nl} and Google geoIP's that exit as IR,
    // so Music UI opens on :9052 but streams/API on :9050 stay unplayable.
    // Keep the whole YT stack on one exit (including googlevideo / youtubei).
    // Also send google.com through the same SOCKS so /sorry captcha isn't
    // served DIRECT (which exposes real RU IP next to the Tor exit).
    if (
        host === "music.youtube.com" || dnsDomainIs(host, ".music.youtube.com") ||
        host === "youtubemusic.com" || dnsDomainIs(host, ".youtubemusic.com") ||
        host === "youtube.com" || dnsDomainIs(host, ".youtube.com") ||
        host === "youtu.be" || dnsDomainIs(host, ".youtu.be") ||
        host === "googlevideo.com" || dnsDomainIs(host, ".googlevideo.com") ||
        host === "ytimg.com" || dnsDomainIs(host, ".ytimg.com") ||
        host === "ggpht.com" || dnsDomainIs(host, ".ggpht.com") ||
        host === "youtube-nocookie.com" || dnsDomainIs(host, ".youtube-nocookie.com") ||
        host === "youtube.googleapis.com" ||
        host === "youtubei.googleapis.com" ||
        host === "youtube-ui.l.google.com" || dnsDomainIs(host, ".youtube-ui.l.google.com") ||
        host === "youtubeembeddedplayer.googleapis.com" ||
        host === "youtubeanalytics.googleapis.com" ||
        host === "jnn-pa.googleapis.com" ||
        host === "wide-youtube.l.google.com" || dnsDomainIs(host, ".wide-youtube.l.google.com") ||
        host === "google.com" || host === "www.google.com" ||
        host === "google.ru" || host === "www.google.ru"
    ) {
        return "SOCKS5 127.0.0.1:9052";
    }

    // Autodesk Forge API — из RU DIRECT часто ломается; :9054 отвечает (Tinkercad и др.)
    if (
        host === "developer.api.autodesk.com" ||
        host === "api.autodesk.com"
    ) {
        return "SOCKS5 127.0.0.1:9054";
    }
    if (
        host === "autodesk.com" || dnsDomainIs(host, ".autodesk.com") ||
        host === "autodesk.net" || dnsDomainIs(host, ".autodesk.net") ||
        host === "autodesk360.com" || dnsDomainIs(host, ".autodesk360.com") ||
        host === "adsk.com" || dnsDomainIs(host, ".adsk.com") ||
        host === "adsk360.com" || dnsDomainIs(host, ".adsk360.com")
    ) {
        return "SOCKS5 127.0.0.1:9050";
    }

    // Telegram DC / infra IPv4 (WebSocket often connects by IP)
    if (
        isInNet(host, "149.154.160.0", "255.255.240.0") ||
        isInNet(host, "91.108.4.0", "255.255.252.0") ||
        isInNet(host, "91.108.8.0", "255.255.252.0") ||
        isInNet(host, "91.108.12.0", "255.255.252.0") ||
        isInNet(host, "91.108.16.0", "255.255.252.0") ||
        isInNet(host, "91.108.20.0", "255.255.252.0") ||
        isInNet(host, "91.108.56.0", "255.255.248.0") ||
        isInNet(host, "95.161.64.0", "255.255.240.0")
    ) {
        return "SOCKS5 127.0.0.1:9050";
    }

    return "DIRECT";
}
