import requests
import urllib3 # 导入 urllib3 来获取版本
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from bs4 import BeautifulSoup
import re
import os

print(f"requests version: {requests.__version__}")
print(f"urllib3 version: {urllib3.__version__}")

# 自定义 HTTPAdapter 以更好地控制 SSL/TLS
class TlsAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        # 创建 SSL 上下文，尝试强制使用 TLSv1.2 或更高版本
        # PROTOCOL_TLS_CLIENT 通常会选择双方都支持的最高版本，并禁用 SSLv2/v3
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        # 也可以显式禁用 SSLv3，尽管 create_default_context 和设置 minimum_version 通常已经足够
        # self.ssl_context.options |= ssl.OP_NO_SSLv3
        
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context,
            **pool_kwargs
        )

# 目标URL列表
urls = ['https://monitor.gacjie.cn/page/cloudflare/ipv4.html',
        'https://ip.164746.xyz'
        ]

# 创建一个会话并挂载自定义适配器
session = requests.Session()
adapter = TlsAdapter()
session.mount('https://', adapter)

# 正则表达式用于匹配IP地址
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# 检查ip.txt文件是否存在,如果存在则删除它
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 创建一个文件来存储IP地址
node_num = 1  # 初始化节点编号
successful_urls = []
failed_urls = []

with open('ip.txt', 'w', encoding='utf-8') as file:  # 指定UTF-8编码
    for url in urls:
        # 发送HTTP请求获取网页内容
        try:
            print(f"Attempting to get URL: {url}")
            response = session.get(url, timeout=10) # 使用会话和自定义适配器,增加超时
            response.raise_for_status() # 如果请求失败则抛出异常
            print(f"Successfully fetched URL: {url}")
            successful_urls.append(url)
        except requests.exceptions.SSLError as e:
            error_message = f"SSL Error: {e}"
            print(f"{error_message} for {url}")
            print("Skipping this URL due to SSL handshake failure.")
            failed_urls.append({"url": url, "reason": error_message})
            continue # 跳过这个URL，继续下一个
        except requests.exceptions.RequestException as e:
            error_message = f"Request Error: {e}"
            print(f"{error_message} for {url}")
            failed_urls.append({"url": url, "reason": error_message})
            continue # 其他请求错误也跳过

        # 使用BeautifulSoup解析HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 根据网站的不同结构找到包含IP地址的元素
        if url == 'https://monitor.gacjie.cn/page/cloudflare/ipv4.html':
            elements = soup.find_all('tr')
        elif url == 'https://ip.164746.xyz':
            elements = soup.find_all('tr')
        else:
            elements = soup.find_all('li')
        
        # 遍历所有元素,查找IP地址
        for element in elements:
            element_text = element.get_text()
            ip_matches = re.findall(ip_pattern, element_text)
            
            # 如果找到IP地址,则写入文件
            for ip in ip_matches:
                file.write(f"{ip}#美国节点{node_num}\n")
                node_num += 1  # 节点编号递增

print('\n--- IP Collection Summary ---')
print('IP地址已保存到ip.txt文件中。')

if successful_urls:
    print("\nSuccessfully fetched IPs from:")
    for url_s in successful_urls:
        print(f"- {url_s}")

if failed_urls:
    print("\nFailed to fetch IPs from:")
    for item in failed_urls:
        print(f"- {item['url']}: {item['reason']}")
print('--- End of Summary ---')
