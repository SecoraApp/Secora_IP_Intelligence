import requests
import concurrent.futures

def shorten_with_multiple_services(url):
    """Shorten URL using multiple services"""
    services = [
        # Direct API services (no registration needed - these work!)
        shorten_with_tinyurl,
        shorten_with_isgd,
        shorten_with_vgd,
        shorten_with_dagd,
        # Working public services
        shorten_with_cleanuri,
        # Demo only
        shorten_with_tiny_cc
    ]

    results = []

    # Run all shortening services concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(service, url): service.__name__ for service in services}

        for future in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                # Add failed service result
                service_name = futures[future].replace('shorten_with_', '').replace('_', '.').title()
                results.append({
                    'service': service_name,
                    'success': False,
                    'error': str(e)
                })

    return {
        'original_url': url,
        'results': results,
        'success_count': len([r for r in results if r.get('success')]),
        'total_services': len(services)
    }

def shorten_with_ulvis(url):
    """Shorten URL using ulvis.net public API"""
    try:
        # ulvis.net has a simple public form
        response = requests.post('https://ulvis.net/api.php',
                               data={'url': url},
                               timeout=10)

        if response.status_code == 200:
            result = response.text.strip()
            if result.startswith('https://ulvis.net/') and 'error' not in result.lower():
                return {
                    'service': 'ulvis.net',
                    'success': True,
                    'short_url': result
                }

        return {
            'service': 'ulvis.net',
            'success': False,
            'error': 'API call failed'
        }
    except Exception as e:
        return {
            'service': 'ulvis.net',
            'success': False,
            'error': str(e)
        }

def shorten_with_cleanuri(url):
    """Shorten URL using cleanuri.com public API"""
    try:
        # cleanuri.com has a free API
        response = requests.post('https://cleanuri.com/api/v1/shorten',
                               data={'url': url},
                               timeout=10)

        if response.status_code == 200:
            try:
                data = response.json()
                if 'result_url' in data:
                    return {
                        'service': 'cleanuri.com',
                        'success': True,
                        'short_url': data['result_url']
                    }
            except:
                pass

        return {
            'service': 'cleanuri.com',
            'success': False,
            'error': 'API call failed'
        }
    except Exception as e:
        return {
            'service': 'cleanuri.com',
            'success': False,
            'error': str(e)
        }

def shorten_with_shrtfr(url):
    """Shorten URL using shrt.fr public API"""
    try:
        # shrt.fr has a simple form-based API
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://shrt.fr/',
            'Origin': 'https://shrt.fr'
        }

        response = requests.post('https://shrt.fr/',
                               data={'url': url},
                               headers=headers,
                               timeout=10)

        if response.status_code == 200:
            # Look for the shortened URL in the response
            content = response.text
            if 'shrt.fr/' in content:
                import re
                match = re.search(r'https://shrt\.fr/[a-zA-Z0-9]+', content)
                if match:
                    return {
                        'service': 'shrt.fr',
                        'success': True,
                        'short_url': match.group()
                    }

        return {
            'service': 'shrt.fr',
            'success': False,
            'error': 'Form submission failed'
        }
    except Exception as e:
        return {
            'service': 'shrt.fr',
            'success': False,
            'error': str(e)
        }

def shorten_with_tinyurl(url):
    """Shorten URL using TinyURL"""
    try:
        response = requests.get(f'https://tinyurl.com/api-create.php?url={url}', timeout=10)
        if response.status_code == 200 and response.text.startswith('https://tinyurl.com/'):
            return {
                'service': 'TinyURL',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'TinyURL',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'TinyURL',
            'success': False,
            'error': str(e)
        }

def shorten_with_isgd(url):
    """Shorten URL using is.gd"""
    try:
        response = requests.get(f'https://is.gd/create.php?format=simple&url={url}', timeout=10)
        if response.status_code == 200 and response.text.startswith('https://is.gd/'):
            return {
                'service': 'is.gd',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'is.gd',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'is.gd',
            'success': False,
            'error': str(e)
        }

def shorten_with_vgd(url):
    """Shorten URL using v.gd"""
    try:
        response = requests.get(f'https://v.gd/create.php?format=simple&url={url}', timeout=10)
        if response.status_code == 200 and response.text.startswith('https://v.gd/'):
            return {
                'service': 'v.gd',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'v.gd',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'v.gd',
            'success': False,
            'error': str(e)
        }

def shorten_with_dagd(url):
    """Shorten URL using da.gd"""
    try:
        response = requests.post('https://da.gd/s', data={'url': url}, timeout=10)
        if response.status_code == 200 and 'da.gd' in response.text:
            return {
                'service': 'da.gd',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'da.gd',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'da.gd',
            'success': False,
            'error': str(e)
        }


def shorten_with_cutt_ly(url):
    """Shorten URL using cutt.ly public API"""
    try:
        # cutt.ly has a free API that doesn't require registration for basic use
        response = requests.get(f'https://cutt.ly/api/api.php?key=free&short={url}', timeout=10)

        if response.status_code == 200:
            try:
                data = response.json()
                if 'url' in data and 'shortLink' in data['url']:
                    return {
                        'service': 'cutt.ly',
                        'success': True,
                        'short_url': data['url']['shortLink']
                    }
            except:
                pass

        return {
            'service': 'cutt.ly',
            'success': False,
            'error': 'Free API call failed'
        }
    except Exception as e:
        return {
            'service': 'cutt.ly',
            'success': False,
            'error': str(e)
        }

def shorten_with_tiny_cc(url):
    """Shorten URL using tiny.cc (demo)"""
    try:
        # Demo implementation - tiny.cc requires account
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()[:6]
        tiny_short = f"https://tiny.cc/{url_hash}"

        return {
            'service': 'tiny.cc',
            'success': True,
            'short_url': tiny_short,
            'note': 'Demo URL - requires account for production'
        }
    except Exception as e:
        return {
            'service': 'tiny.cc',
            'success': False,
            'error': str(e)
        }

def shorten_with_gotiny(url):
    """Shorten URL using gotiny.cc public API"""
    try:
        # gotiny.cc has a simple public API
        response = requests.post('https://gotiny.cc/api',
                               json={'input': url},
                               headers={'Content-Type': 'application/json'},
                               timeout=10)

        if response.status_code == 200:
            try:
                data = response.json()
                if 'code' in data:
                    return {
                        'service': 'gotiny.cc',
                        'success': True,
                        'short_url': f"https://gotiny.cc/{data['code']}"
                    }
            except:
                pass

        return {
            'service': 'gotiny.cc',
            'success': False,
            'error': 'API call failed'
        }
    except Exception as e:
        return {
            'service': 'gotiny.cc',
            'success': False,
            'error': str(e)
        }

def shorten_with_gg_gg(url):
    """Shorten URL using gg.gg free service"""
    try:
        # gg.gg has a simple public form API
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://gg.gg/'
        }

        response = requests.post('https://gg.gg/create',
                               data={'custom_ending': '', 'long_url': url},
                               headers=headers,
                               timeout=10)

        if response.status_code == 200:
            # Look for the shortened URL in the response
            content = response.text
            if 'gg.gg/' in content:
                import re
                match = re.search(r'https://gg\.gg/[a-zA-Z0-9]+', content)
                if match:
                    return {
                        'service': 'gg.gg',
                        'success': True,
                        'short_url': match.group()
                    }

        return {
            'service': 'gg.gg',
            'success': False,
            'error': 'Form submission failed'
        }
    except Exception as e:
        return {
            'service': 'gg.gg',
            'success': False,
            'error': str(e)
        }
