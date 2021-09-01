import ipaddress
import re
import socket
import tldextract
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import whois
from datetime import datetime, timezone
import urllib.request, sys, re
import xmltodict, json

import ssl
from datetime import date

class UrlFeaturizer(object):
    def __init__(self, url):
        self.url = url
        self.domain = url.split('//')[-1].split('/')[0]
        self.today = datetime.now().replace(tzinfo=None)

        try:
            self.response = requests.get(self.url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = ""
            self.soup = -999



    def usingIP(self):
        try:
            ipaddress.ip_address(self.domain)
            ip = -1
        except:
            ip = 1
        return ip

    def hasLongURL(self):
       if len(self.url) < 54:
           return 1
       elif len(self.url) <= 75 and len(self.url) >= 54:
           return 0
       else:
           return -1

    def hasShortURL(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net|rb\.gy|on\.com',
                          self.url)
        if match:
            return -1
        else:
            return 1

    def haveAtSign(self):
        if "@" in self.url:
            at = -1
        else:
            at = 1
        return at

    def redirectSlash(self):
        pos = self.url.rfind('//')
        if pos > 6:
            if pos > 7:
                return -1
            else:
                return 1
        else:
            return 1

    def prefixSuffix(self):
        if '-' in urlparse(self.url).netloc:
            return -1  # phishing
        else:
            return 1  # legitimate

    def numSubDomains(self):
        dom = self.domain.split('www.')[-1]
        num = dom.count('.')
        match = re.search('.ac|.ad|.ae|.af|.ag|.ai|.al|.am|.an|.ao|.aq|.ar|.as|.at|.au|.aw|.ax|.az|.ba|.bb|.bd|.be|.bf|.bg|.bh|.bi|.bj|.bm|.bn|.bo|'
                          '.br|.bs|.bt|.bv|.bw|.by|.bz|.ca|.cc|.cd|.cf|.cg|.ch|.ci|.ck|.cl|.cm|.cn|.co|.cr|.cs|.cu|.cv|.cw|.cx|.cy|.cz|.dd|.de|.dj|'
                          '.dk|.dm|.do|.dz|.ec|.ee|.eg|.eh|.er|.es|.et|.eu|.fi|.fj|.fk|.fm|.fo|.fr|.ga|.gb|.gd|.ge|.gf|.gg|.gh|.gi|.gl|.gm|.gn|.gp|'
                          '.gq|.gr|.gs|.gt|.gu|.gw|.gy|.hk|.hm|.hn|.hr|.ht|.hu|.id|.ie|.il|.im|.in|.io|.iq|.ir|.is|.it|.je|.jm|.jo|.jp|.ke|.kg|.kh|'
                          '.ki|.km|.kn|.kp|.kr|.kw|.ky|.kz|.la|.lb|.lc|.li|.lk|.lr|.ls|.lt|.lu|.lv|.ly|.ma|.mc|.md|.me|.mg|.mh|.mk|.ml|.mm|.mn|.mo|'
                          '.mp|.mq|.mr|.ms|.mt|.mu|.mv|.mw|.mx|.my|.mz|.na|.nc|.ne|.nf|.ng|.ni|.nl|.no|.np|.nr|.nu|.nz|.om|.pa|.pe|.pf|.pg|.ph|.pk|'
                          '.pl|.pm|.pn|.pr|.ps|.pt|.pw|.py|.qa|.re|.ro|.rs|.ru|.rw|.sa|.sb|.sc|.sd|.se|.sg|.sh|.si|.sj|.sk|.sl|.sm|.sn|.so|.sr|.ss|'
                          '.st|.su|.sv|.sx|.sy|.sz|.tc|.td|.tf|.tg|.th|.tj|.tk|.tl|.tm|.tn|.to|.tp|.tr|.tt|.tv|.tw|.tz|.ua|.ug|.uk|.us|.uy|.uz|.va|'
                          '.vc|.ve|.vg|.vi|.vn|.vu|.wf|.ws|.ye|.yt|.yu|.za|.zm|.zw', dom)
        if match:
            num -= 1
        if num <= 1:
            return 1
        elif num == 2:
            return 0
        else:
            return -1

    def validHttps(self):
        hostname = self.domain
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    match = re.search(
                        'Certum|VeriSign|Comodo|DigiCert|Entrust|GeoTrust|GlobalSign|GoDaddy|QuoVadis|RapidSSL|USERTrust (Sectigo)|Sectigo|USERTrust|Symantec|Thawte|Network Solutions|SSL.com',
                        cert['issuer'][1][0][1])
                    if match:
                        return 1
                    elif not match:
                        return 0
        except:
            return -1

    def domRegLen(self):
        try:
            whois_info = whois.whois(self.domain)
            end = whois_info.expiration_date
            start = whois_info.creation_date
            l_date = date(end.year, end.month, end.day)
            f_date = date(start[0].year, start[0].month, start[0].day)
            delta = l_date - f_date
            if delta.days <= 365:
                return -1
            else:
                return 1
        except:
            return -1

    def favicon(self):
        if self.soup == -999:
            return -1
        else:
            try:
                for head in self.soup.find_all('head'):
                    for head.link in self.soup.find_all('link'):
                        dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                        if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                            return 1
                            raise StopIteration
                        else:
                            return -1
                            raise StopIteration
            except StopIteration:
                pass

    def nonStandPort(self):
        try:
            port = self.domain.split(":")[1]
            if port == 80 or port == 443:
                return 1
            if port:
                return -1
            else:
                return 1
        except:
            return 1

    def httpsDom(self):
        if 'https' in self.domain:
            return -1
        else:
            return 1

    def requestUrl(self):
        i = 0
        success = 0
        if self.soup == -999:
            return -1
        else:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif ((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 1


    def anchorUrl(self):
        a_tags = self.soup.find_all('a')
        if len(a_tags) == 0:
            return 1

        invalid = ['#', '#content', '#skip', 'JavaScript::void(0)']
        bad_count = 0
        for t in a_tags:
            try:
                link = t['href']
            except KeyError:
                continue

            if link in invalid:
                bad_count += 1
            try:
                requests.get(link)
                url_ref2 = link.split('//')[-1].split('/')[0]
                if self.domain not in url_ref2:
                    bad_count += 1
            except:
                continue

        bad_count /= len(a_tags)
        if bad_count < 0.31:
            return 1
        elif bad_count <= 0.67:
            return 0
        return -1

    def linksInScriptTags(self):
        mtags = self.soup.find_all('Meta')
        ud = tldextract.extract(self.url)
        upage = ud.domain
        mcount = 0
        for i in mtags:
            u1 = i['href']
            currpage = tldextract.extract(u1)
            u1page = currpage.domain
            if currpage not in u1page:
                mcount += 1
        scount = 0
        stags = self.soup.find_all('Script')
        for j in stags:
            u1 = j['href']
            currpage = tldextract.extract(u1)
            u1page = currpage.domain
            if currpage not in u1page:
                scount += 1
        lcount = 0
        ltags = self.soup.find_all('Link')
        for k in ltags:
            u1 = k['href']
            currpage = tldextract.extract(u1)
            u1page = currpage.domain
            if currpage not in u1page:
                lcount += 1
        percmtag = 0
        percstag = 0
        percltag = 0

        if len(mtags) != 0:
            percmtag = (mcount * 100) // len(mtags)
        if len(stags) != 0:
            percstag = (scount * 100) // len(stags)
        if len(ltags) != 0:
            percltag = (lcount * 100) // len(ltags)

        if (percmtag + percstag + percltag < 17):
            return 1
        elif (percmtag + percstag + percltag <= 81):
            return 0
        return -1

    def sfh(self):
        try:
            f = str(self.soup.form)
            ac = f.find("action")
            if (ac != -1):
                i1 = f[ac:].find(">")
                u1 = f[ac + 8:i1 - 1]
                if (u1 == "" or u1 == "about:blank"):
                    return -1
                upage = self.domain
                erl2 = tldextract.extract(u1)
                usfh = erl2.domain
                if upage in usfh:
                    return 1
                return 0
            else:
                # Check this point
                return 1
        except:
            # Check this point
            return 1

    def infoEmail(self):
        form_opt = str(self.soup.form)
        idx = form_opt.find("mail()")
        if idx == -1:
            idx = form_opt.find("mailto:")

        if idx == -1:
            return 1
        return -1

    def abnormalUrl(self):
        if self.response == "":
            return -1
        else:
            if self.response.text == "":
                return -1
            else:
                return 1

    def webForward(self):
        if self.response == "":
            return -1
        else:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1

    def statusBarCust(self):
        if str(self.soup).lower().find('onmouseover="window.status') != -1:
            return -1
        return 1


    def disableRightClick(self):
        try:
            iframe = re.findall(r"event.button ?== ?2", self.response.text)
            if len(iframe):
                return -1
            else:
                return 1
        except:
            return 1

    def popupWindow(self):
        if self.response == "":
            return -1
        else:
            if re.findall(r"prompt\(", self.response.text):
                return -1
            else:
                return 1

    def iFrameRed(self):
        try:
            iframe = re.findall(r"<iframe", self.response.text)
            if len(iframe) > 0:
                return -1
            else:
                return 1
        except:
            return 1

    def domAge(self):
        try:
            whois_info = whois.whois(self.domain)
            start = whois_info.creation_date
            f_date = date(start[0].year, start[0].month, start[0].day)
            today = datetime.today()
            todayFormat = date(today.year, today.month, today.day)
            delta = todayFormat - f_date
            if delta.days >= 182.5:
                return 1
            else:
                return -1
        except:
            return -1



    def dnsRecord(self):
        try:
            d = whois.whois(self.domain)
            return 1
        except:
            return -1

    def webTraff(self):

        try:
            xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(self.domain)).read()

            result = xmltodict.parse(xml)

            data = json.dumps(result).replace("@", "")
            data_tojson = json.loads(data)
            url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
            rank = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"]
            rank = int(rank)
            if rank < 100000:
                return 1
            else:
                return 0
        except:
            return -1



    def pageRank(self):
        try:
            xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(self.domain)).read()

            result = xmltodict.parse(xml)

            data = json.dumps(result).replace("@", "")
            data_tojson = json.loads(data)
            url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
            rank = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"]
            rank = int(rank)
            if rank < 100000:
                return 1
            else:
                return 0
        except:
            return -1


    def googleIndex(self):
        site = search(self.url, 5)
        if site:
            return 1
        else:
            return -1

    def linksPointingToPage(self):
        try:
            find = "href=" + '"{}"'.format('https://' + self.domain)
            linkFind = re.findall(find, self.response.text)
            number_of_links = len(linkFind)
            if number_of_links == 0:
                return -1
            elif number_of_links <= 2:
                return 0
            else:
                return 1

        except:
            return -1


    def statReport(self):
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
            self.url)
        try:
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address)
            if url_match or ip_match:
                return -1
            else:
                return 1
        except:
            return -1

    def run(self):
        try:
            whois.whois(self.url)
            data = []
            data.insert(0, self.usingIP())
            data.insert(1, self.hasLongURL())
            data.insert(2, self.hasShortURL())
            data.insert(3, self.haveAtSign())
            data.insert(4, self.redirectSlash())
            data.insert(5, self.prefixSuffix())
            data.insert(6, self.numSubDomains())
            data.insert(7, self.validHttps())
            data.insert(8, self.domRegLen())
            data.insert(9, self.favicon())
            data.insert(10, self.nonStandPort())
            data.insert(11, self.httpsDom())
            data.insert(12, self.requestUrl())
            data.insert(13, self.anchorUrl())
            data.insert(14, self.linksInScriptTags())
            data.insert(15, self.sfh())
            data.insert(16, self.infoEmail())
            data.insert(17, self.abnormalUrl())
            data.insert(18, self.webForward())
            data.insert(19, self.statusBarCust())
            data.insert(20, self.disableRightClick())
            data.insert(21, self.popupWindow())
            data.insert(22, self.iFrameRed())
            data.insert(23, self.domAge())
            data.insert(24, self.dnsRecord())
            data.insert(25, self.webTraff())
            data.insert(26, self.pageRank())
            data.insert(27, self.googleIndex())
            data.insert(28, self.linksPointingToPage())
            data.insert(29, self.statReport())
            return data
        except:
            return 'Non-Existent'
        # data = self.pageRank()





