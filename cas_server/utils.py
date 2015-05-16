import urlparse
import urllib

def update_url(url, params):
    url = urlparse.urlparse(url)
    url_parts = list(urlparse.urlparse(service))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urllib.urlencode(query)
    return urlparse.urlunparse(url_parts)
