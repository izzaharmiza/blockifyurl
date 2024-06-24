import ipaddress
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import whois
from datetime import datetime
import socket
from googlesearch import search

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.features = []
        self.setup()

    def setup(self):
        try:
            self.response = requests.get(self.url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.RequestException:
            self.response = None
            self.soup = None

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception:
            self.whois_response = None

        self.extract_features()

    def extract_features(self):
        self.features = [
            self.UsingIP(),
            self.LongURL(),
            self.ShortURL(),
            self.SymbolAt(),
            self.Redirecting(),
            self.PrefixSuffix(),
            self.SubDomains(),
            self.HTTPS(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]
        print(f"Extracted Features: {self.features}")

    def UsingIP(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except ValueError:
            return 1

    def LongURL(self):
        return -1 if len(self.url) > 54 else 1

    def ShortURL(self):
        return -1 if any(service in self.url for service in ["bit.ly", "t.co", "goo.gl", "ow.ly"]) else 1

    def SymbolAt(self):
        return -1 if "@" in self.url else 1

    def Redirecting(self):
        return -1 if "//" in self.url[self.url.find("//")+2:] else 1

    def PrefixSuffix(self):
        return -1 if '-' in self.domain else 1

    def SubDomains(self):
        if self.domain.count(".") > 2:
            return -1
        return 1 if self.domain.count(".") == 1 else 0

    def HTTPS(self):
        return 1 if self.parsed_url.scheme == "https" else -1

    def DomainRegLen(self):
        try:
            if self.whois_response:
                creation_date = self.whois_response.creation_date
                expiration_date = self.whois_response.expiration_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                age = (expiration_date - creation_date).days // 365
                return 1 if age >= 1 else -1
            return -1
        except:
            return -1

    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1

    def RequestURL(self):
        try:
            success, i = 0, 0
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success += 1
                i += 1

            if i == 0:
                return 0
            percentage = success / float(i) * 100
            if percentage < 22.0:
                return 1
            elif percentage < 61.0:
                return 0
            else:
                return -1
        except:
            return -1

    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                i += 1

            if i == 0:
                return 0
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                return 1
            elif percentage < 67.0:
                return 0
            else:
                return -1
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success += 1
                i += 1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success += 1
                i += 1

            if i == 0:
                return 0
            percentage = success / float(i) * 100
            if percentage < 17.0:
                return 1
            elif percentage < 81.0:
                return 0
            else:
                return -1
        except:
            return -1

    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                return 1
            else:
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup):
                return -1
            else:
                return 1
        except:
            return -1

    def AbnormalURL(self):
        try:
            if self.response and self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def IframeRedirection(self):
        try:
            if re.findall(r"<iframe>|<frameborder>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def AgeofDomain(self):
        try:
            if self.whois_response:
                creation_date = self.whois_response.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.now() - creation_date).days // 365
                return 1 if age >= 1 else -1
            return -1
        except:
            return -1

    def DNSRecording(self):
        try:
            if self.whois_response:
                creation_date = self.whois_response.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.now() - creation_date).days // 365
                return 1 if age >= 1 else -1
            return -1
        except:
            return -1

    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            if int(rank) < 100000:
                return 1
            return 0
        except:
            return -1

    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    def StatsReport(self):
        try:
            url_match = re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except:
            return 1

    def get_features(self):
        return self.features

# Example usage
url = "http://example.com"
features_extractor = FeatureExtraction(url)
features = features_extractor.get_features()
print(features)
