# 0 - INDICATES LEGITIMATE URL
# 1 - INDICATES PHISHING URL
# 2 - INDICATES SUSPICIOUS URL
import pandas as pd
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import whois
import urllib.request
import time
import socket
from urllib.error import HTTPError
from datetime import  datetime

class Feature:
    def __init__(self):
        pass
    #CHECKING THE IP
    def havingIP(self,URL):
        check=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',URL)    
        if check:
            return 1      
        else:
            return 0       
    #LENGTH OF THE URL
    def long_url(self,url):
        length=len(url)
        if length < 54:
            return 0           
        elif length >= 54 and length <= 75:
            return 2           
        else:
            return 1           
    #CHECKING THE @ SYMBOL
    def have_at_symbol(self,url):
        check="@" in url
        if check:
            return 1           
        else:
            return 0           
    #CHECKING THE // SYMBOL AFTER PROTOCOL AND CLASSIFYING THE URL HAVING // AS PHISHING
    def redirection(self,url):   
        check="//" in urlparse(url).path    
        if check:
            return 1           
        else:
            return 0            
    #CHECKING THE - SYMBOL AND IF THE URL HAS IT IT'S CONSIDERED AS A PHISHING SITE
    def prefix_suffix_separation(self,url):
        check="-" in urlparse(url).netloc
        if check:
            return 1          
        else:
            return 0          
    #CHECKING NUMBER OF DOTS IN THE URL AND IF THE NUMBER OF DOTS ARE MORE THAT 3 THAN IT IS CONSIDERED AS PHISHING
    def sub_domains(self,url):
        count=url.count(".")
        if count < 3:
            return 0           
        elif count == 3:
            return 2         
        else:
            return 1           
    #CHECKING THE TINY URL WHICH IMPLIES PHISHING OTHERWISE LEGITIMATE
    def shortening_service(self,url):
        check=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if check:
            return 1           
        else:
            return 0              

    #CHECKING THE WEB TRAFFIC OF THE URL
    def web_traffic(self,url):
        try:
            rank = int(BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK'])
        except TypeError:
            return 1
        except HTTPError:
            return 2
        if (rank<100000):
            return 0
        else:
            return 2
    #CHECKING THE VALUE CAN BE OBTAINED FROM A LIST OR NOT INDICATING THE URL IS PHISHING OR NOT
    def domain_registration_length(self,url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1

        if dns == 1:
            return 1    
        else:
            expiration_date = domain_name.expiration_date
            to = time.strftime('%Y-%m-%d')
            to = datetime.strptime(to, '%Y-%m-%d')
            if expiration_date is None:
                return 1
            elif type(expiration_date) is list or type(to) is list :
                return 2     
            else:
                create_date = domain_name.creation_date
                expire_date = domain_name.expiration_date
                x=isinstance(create_date,str)
                y=isinstance(expire_date,str)
                if (x or y):
                    try:
                        create_date = datetime.strptime(create_date,'%Y-%m-%d')
                        expire_date = datetime.strptime(expire_date,"%Y-%m-%d")
                    except:
                        return 2
                value=(expire_date - to)
                length_of_registration = abs(value.days)
                req_val=length_of_registration/365
                if req_val <= 1:
                    return 1 
                else:
                    return 0 
    #CHECKING THE DOMAIN AGE OF THE URL
    def age_domain(self,url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1

        if dns == 1:
            return 1
        else:
            create_date = domain_name.creation_date
            expire_date = domain_name.expiration_date
            x=isinstance(create_date,str)
            y=isinstance(expire_date,str)
            if (x or y):
                try:
                    create_date = datetime.strptime(create_date,'%Y-%m-%d')
                    expire_date = datetime.strptime(expire_date,"%Y-%m-%d")
                except:
                    return 2
            if ((expire_date is None) or (create_date is None)):
                return 1
            elif ((type(expire_date) is list) or (type(create_date) is list)):
                return 2
            else:
                ageofdomain = abs((expire_date - create_date).days)
                req_val=(ageofdomain/30) 
                if (req_val < 6):
                    return 1
                else:
                    return 0

    #CHECKING THE RECORD OF THE URL
    def dns_record(self,url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1

        if dns == 1:
            return 1
        else:
            return 0

    #GETTING THE STATISTICAL REPORT OF THE URL
    def statistical_report(self,url):
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0:
                hostname = hostname[:h[0][0]]
        url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
        except:
            return 1

        if url_match:
            return 1
        else:
            return 0
    #CHECKING THE HTTPS IN THE URL
    def https_token(self,url):
        match=re.search('https://|http://',url)
        try:
            if match.start(0)==0 and match.start(0) is not None:
                url=url[match.end(0):]
                match=re.search('http|https',url)
                if match:
                    return 1
                else:
                    return 0
        except:
            return 1
# object creation
def getAttributess(url):

    f = Feature()
    having_ip = f.havingIP(url)
    len_url = f.long_url(url)
    having_at_symbol = f.have_at_symbol(url)
    redirection_symbol = f.redirection(url)
    prefix_suffix_separation = f.prefix_suffix_separation(url)
    sub_domains = f.sub_domains(url)
    tiny_url = f.shortening_service(url)
    web_traffic = f.web_traffic(url)
    domain_registration_length = f.domain_registration_length(url)
    dns_record = f.dns_record(url)
    statistical_report = f.statistical_report(url)
    age_domain = f.age_domain(url)
    http_tokens = f.https_token(url)

    d={'Having_IP':pd.Series(having_ip),
   'URL_Length':pd.Series(len_url),'Having_@_symbol':pd.Series(having_at_symbol),
   'Redirection_//_symbol':pd.Series(redirection_symbol),'Prefix_suffix_separation':pd.Series(prefix_suffix_separation),
   'Sub_domains':pd.Series(sub_domains),'tiny_url':pd.Series(tiny_url),'web_traffic' : pd.Series(web_traffic),
   'domain_registration_length':pd.Series(domain_registration_length),'dns_record':pd.Series(dns_record),
   'statistical_report':pd.Series(statistical_report),'age_domain':pd.Series(age_domain),'http_tokens':pd.Series(http_tokens)}
    data=pd.DataFrame(d)
    return data