# coding=utf-8
"""
歪比巴卜.py - 视频解析爬虫
适用于 TVBox / 蜂蜜影视 (Spider 规范)
"""

import sys
import os
import re
import json
import urllib.parse
import hashlib
import base64
import time
from base.spider import Spider
from bs4 import BeautifulSoup

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


class Spider(Spider):
    def __init__(self):
        super().__init__()
        self.host = ""
        self.playerHost = ""
        self.playurl = ""

    def getName(self):
        return "歪比巴卜"

    def init(self, extend=""):
        self.host = "https://wbbb1.com"
        # 尝试两个可能的解析器域名
        self.playerHost = "https://xn--qvr2v.850088.xyz"
        self.playurl = "https://xn--qvr2v.850088.xyz/player/?url="
        print(f"Initialized 歪比巴卜 host: {self.host}")
        print(f"PlayerHost: {self.playerHost}")

    def getDependence(self):
        return ["bs4", "Crypto"]

    def header(self):
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0',
            'Referer': self.host + '/',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'X-Requested-With': 'XMLHttpRequest',
        }

    def videoHeader(self):
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0',
            'Referer': self.host + '/',
            'Origin': self.playerHost,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
        }

    # ==================== 解密相关 ====================

    def md5(self, text):
        if isinstance(text, str):
            text = text.encode('utf-8')
        return hashlib.md5(text).hexdigest()

    def calculate(self, url_value):
        return (self.md5(url_value) + " P")[-22:]

    def rc4_crypt(self, key, data):
        S = list(range(256))
        key_bytes = [ord(c) for c in key] if isinstance(key, str) else list(key)
        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        data_bytes = [ord(c) for c in data] if isinstance(data, str) else list(data)
        result = []
        for byte in data_bytes:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            result.append(byte ^ S[t])
        return bytes(result)

    def enplay(self, raw_str, url_value):
        """
        对应 JS 的 enplay(str) 函数:
        - 使用 calculate(urlValueurl) 作为 RC4 密钥
        - 对字符串进行 RC4 加密
        - 使用 btoa 编码（等价于 encode('latin-1').base64）
        """
        key = self.calculate(url_value)
        # RC4 字符串加密（对应 JS aesplay）
        encrypted = self._rc4_str(key, raw_str)
        # btoa 等价于 encode('latin-1').base64
        return base64.b64encode(encrypted.encode('latin-1')).decode('ascii')

    def _rc4_str(self, key: str, data: str) -> str:
        """
        RC4 字符串加解密（对应 JS aesplay 函数）。
        操作字符级别而非字节级别。
        """
        S = list(range(256))
        key_codes = [ord(c) for c in key]
        j = 0
        for i in range(256):
            j = (j + S[i] + key_codes[i % len(key_codes)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        result = []
        for ch in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            result.append(chr(ord(ch) ^ S[t]))
        return "".join(result)

    def deplay(self, encoded_str, url_value):
        """
        对应 crypto.py 的 parser_deplay:
        1. base64 解码
        2. latin-1 解码为字符串
        3. RC4 字符串解密
        """
        key = self.calculate(url_value)
        raw = base64.b64decode(encoded_str).decode("latin-1")
        return self._rc4_str(key, raw)

    def decryptVideoUrl(self, encrypted_url_b64, aes_key_enc, aes_iv_enc, url_value):
        """
        解密 api.php 返回的视频地址。
        
        流程：
          1. deplay(aes_key_enc) → 真实 AES key (字符串)
          2. deplay(aes_iv_enc)  → 真实 AES iv (字符串)
          3. AES-CBC-PKCS7 解密 encrypted_url → 真实视频地址
        """
        if not _HAS_CRYPTO:
            print("错误: 需要安装 pycryptodome")
            return None
        # deplay 返回字符串，需要 encode 为 bytes 供 AES 使用
        decrypted_key = self.deplay(aes_key_enc, url_value).encode('utf-8')
        decrypted_iv = self.deplay(aes_iv_enc, url_value).encode('utf-8')
        encrypted_bytes = base64.b64decode(encrypted_url_b64)
        cipher = AES.new(decrypted_key, AES.MODE_CBC, iv=decrypted_iv)
        decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        return decrypted.decode('utf-8')

    def buildApiParams(self, video_url, play_page_url=""):
        """
        构建 api.php POST 请求参数。
        
        参考 可读.js:
        - url: 加密 URL（不含 next）
        - key = enplay(md5(url + "stray"))
        - vkey = enplay(time + md5(calculate(url) + "stray"))
        - ckey = enplay(md5(host + "stray"))
        
        注意: next 参数在 JS 中是独立的 URL 查询参数，
              不拼接到 POST 的 url 字段中。
        """
        ts = str(int(time.time()))
        
        # 使用原始加密 URL 作为 url 值（不拼接 next）
        url_for_post = video_url
        
        # key = enplay(md5(url + "stray"))
        key_val = self.enplay(self.md5(url_for_post + "stray"), url_for_post)
        # vkey = enplay(ts + md5(calculate(url) + "stray"))
        vkey_val = self.enplay(ts + self.md5(self.calculate(url_for_post) + "stray"), url_for_post)
        # ckey = enplay(md5(host + "stray"))
        # 注意：JS 中使用 window.location.host，不包含协议
        host_only = self.playerHost.replace('https://', '').replace('http://', '')
        ckey_val = self.enplay(self.md5(host_only + "stray"), url_for_post)
            
        return {"url": url_for_post, "key": key_val, "vkey": vkey_val, "ckey": ckey_val}

    # ==================== 工具方法 ====================

    def build_full_url(self, url):
        if not url or not isinstance(url, str):
            return ''
        url = url.strip()
        if url.startswith('http://') or url.startswith('https://'):
            return url
        if url in ['null', 'undefined', '']:
            return ''
        if url.startswith('//'):
            return 'https:' + url
        if url.startswith('/'):
            return self.host + url
        if url.startswith('./'):
            return self.host + url[1:]
        return self.host + '/' + url

    def extract_remark(self, element):
        note = element.find('div', class_='module-item-note')
        return note.text.strip() if note else ''

    # ==================== homeContent ====================

    def homeContent(self, filter=False):
        result = {}
        classes = [
            {"type_id": "1", "type_name": "电影"},
            {"type_id": "2", "type_name": "剧集"},
            {"type_id": "3", "type_name": "动漫"},
            {"type_id": "4", "type_name": "综艺"},
            {"type_id": "5", "type_name": "短剧"},
        ]
        result["class"] = classes

        # 统一的筛选器选项
        CLASS_OPTIONS = [{"n": "全部", "v": ""}, {"n": "喜剧", "v": "喜剧"}, {"n": "爱情", "v": "爱情"}, {"n": "恐怖", "v": "恐怖"}, {"n": "动作", "v": "动作"}, {"n": "科幻", "v": "科幻"}, {"n": "剧情", "v": "剧情"}, {"n": "战争", "v": "战争"}, {"n": "警匪", "v": "警匪"}, {"n": "犯罪", "v": "犯罪"}, {"n": "动画", "v": "动画"}, {"n": "奇幻", "v": "奇幻"}, {"n": "武侠", "v": "武侠"}, {"n": "冒险", "v": "冒险"}]
        AREA_OPTIONS = [{"n": "全部", "v": ""}, {"n": "大陆", "v": "大陆"}, {"n": "港台", "v": "港台"}, {"n": "美国", "v": "美国"}, {"n": "韩国", "v": "韩国"}, {"n": "日本", "v": "日本"}, {"n": "泰国", "v": "泰国"}, {"n": "印度", "v": "印度"}, {"n": "法国", "v": "法国"}, {"n": "英国", "v": "英国"}]
        LANG_OPTIONS = [{"n": "全部", "v": ""}, {"n": "国语", "v": "国语"}, {"n": "粤语", "v": "粤语"}, {"n": "韩语", "v": "韩语"}, {"n": "日语", "v": "日语"}, {"n": "英语", "v": "英语"}, {"n": "泰语", "v": "泰语"}]
        YEAR_OPTIONS = [{"n": "全部", "v": ""}] + [{"n": str(y), "v": str(y)} for y in range(2025, 2009, -1)]
        LETTER_OPTIONS = [{"n": "全部", "v": ""}] + [{"n": c, "v": c} for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] + [{"n": "0-9", "v": "0-9"}]
        SORT_OPTIONS = [{"n": "时间", "v": "time"}, {"n": "人气", "v": "hits"}, {"n": "评分", "v": "score"}]

        # 所有分类使用相同的筛选器
        COMMON_FILTERS = [
            {"key": "class", "name": "剧情", "value": CLASS_OPTIONS},
            {"key": "area", "name": "地区", "value": AREA_OPTIONS},
            {"key": "lang", "name": "语言", "value": LANG_OPTIONS},
            {"key": "year", "name": "年份", "value": YEAR_OPTIONS},
            {"key": "letter", "name": "字母", "value": LETTER_OPTIONS},
            {"key": "by", "name": "排序", "value": SORT_OPTIONS},
        ]

        filters = {
            "1": COMMON_FILTERS,
            "2": COMMON_FILTERS,
            "3": COMMON_FILTERS,
            "4": COMMON_FILTERS,
            "5": COMMON_FILTERS,
        }
        result["filters"] = filters

        try:
            rsp = self.fetch(self.host, headers=self.header())
            soup = BeautifulSoup(rsp.text, 'html.parser')
            videos = []
            banner_links = soup.select('.swiper-big a.banner')
            for item in banner_links:
                href = item.get('href', '')
                img = item.find('img')
                title = item.get('title', '') or (img.get('alt', '') if img else '')
                pic = img.get('data-original', '') or img.get('src', '') if img else ''
                if href and title:
                    videos.append({"vod_id": href, "vod_name": title, "vod_pic": self.build_full_url(pic), "vod_remarks": "轮播推荐"})
            hot_items = soup.select('.module-poster-items-base > a.module-poster-item')
            for item in hot_items[:20]:
                href = item.get('href', '')
                title = item.get('title', '').strip()
                img = item.find('img')
                pic = img.get('data-original', '') or img.get('src', '') if img else ''
                remark = self.extract_remark(item)
                if title and href:
                    videos.append({"vod_id": href, "vod_name": title, "vod_pic": self.build_full_url(pic), "vod_remarks": remark})
            seen = set()
            unique_videos = []
            for v in videos:
                if v['vod_id'] not in seen and v['vod_name']:
                    seen.add(v['vod_id'])
                    unique_videos.append(v)
                    if len(unique_videos) >= 20:
                        break
            result["list"] = unique_videos
        except Exception as e:
            print(f"homeContent error: {e}")
            result["list"] = []
        return result

    def homeVideoContent(self):
        result = {}
        try:
            rsp = self.fetch(self.host, headers=self.header())
            soup = BeautifulSoup(rsp.text, 'html.parser')
            videos = []
            banner_links = soup.select('.swiper-big a.banner')
            for item in banner_links:
                href = item.get('href', '')
                img = item.find('img')
                title = item.get('title', '') or (img.get('alt', '') if img else '')
                pic = img.get('data-original', '') or img.get('src', '') if img else ''
                if href and title:
                    videos.append({"vod_id": href, "vod_name": title, "vod_pic": self.build_full_url(pic), "vod_remarks": "轮播推荐"})
            hot_items = soup.select('.module-poster-items-base > a.module-poster-item')
            for item in hot_items[:20]:
                href = item.get('href', '')
                title = item.get('title', '').strip()
                img = item.find('img')
                pic = img.get('data-original', '') or img.get('src', '') if img else ''
                remark = self.extract_remark(item)
                if title and href:
                    videos.append({"vod_id": href, "vod_name": title, "vod_pic": self.build_full_url(pic), "vod_remarks": remark})
            seen = set()
            unique_videos = []
            for v in videos:
                if v['vod_id'] not in seen and v['vod_name']:
                    seen.add(v['vod_id'])
                    unique_videos.append(v)
                    if len(unique_videos) >= 20:
                        break
            result["list"] = unique_videos
        except Exception as e:
            print(f"homeVideoContent error: {e}")
            result["list"] = []
        return result

    def categoryContent(self, tid, pg, filter, extend):
        result = {}
        try:
            area = extend.get('area', '') or ''
            class_filter = extend.get('class', '') or ''
            lang = extend.get('lang', '') or ''
            year = extend.get('year', '') or ''
            letter = extend.get('letter', '') or ''
            pg_int = int(pg) if pg else 1

            if area or class_filter or lang or year or letter:
                area_part = '-' + area if area else ''
                class_part = '--' + class_filter if class_filter else ''
                lang_part = lang if lang else ''
                letter_part = letter if letter else ''
                year_part = '------' + year if year else ''
                pg_part = str(pg_int) if pg_int > 1 else ''
                url = f"{self.host}/show/{tid}{area_part}{class_part}-{lang_part}-{letter_part}{year_part}---{pg_part}---.html"
            else:
                url = f"{self.host}/type/{tid}-{pg_int}.html" if pg_int > 1 else f"{self.host}/type/{tid}.html"

            print(f"Fetching category: {url}")
            rsp = self.fetch(url, headers=self.header())
            soup = BeautifulSoup(rsp.text, 'html.parser')
            videos = []
            items = soup.select('.module-items .module-poster-item')
            for item in items:
                href = item.get('href', '')
                title = item.get('title', '').strip()
                img = item.find('img')
                pic = img.get('data-original', '') or img.get('src', '') if img else ''
                remark = self.extract_remark(item)
                if title and href:
                    videos.append({"vod_id": href, "vod_name": title, "vod_pic": self.build_full_url(pic), "vod_remarks": remark})
            result["list"] = videos
            result["page"] = pg_int
            result["pagecount"] = pg_int + 1 if len(videos) >= 20 else pg_int
            result["limit"] = 20
            result["total"] = pg_int * 20
        except Exception as e:
            print(f"categoryContent error: {e}")
            result = {"list": [], "pagecount": 1, "page": 1, "limit": 0, "total": 0}
        return result

    def detailContent(self, ids):
        result = {}
        try:
            vid = ids[0] if isinstance(ids, list) else ids
            vid = self.build_full_url(vid)
            print(f"Fetching detail: {vid}")
            rsp = self.fetch(vid, headers=self.header())
            soup = BeautifulSoup(rsp.text, 'html.parser')

            vod = {"vod_id": vid, "vod_name": "", "vod_pic": "", "vod_actor": "", "vod_director": "", "vod_content": "", "vod_area": "", "vod_year": "", "vod_remarks": "", "type_name": "", "vod_play_from": "", "vod_play_url": ""}

            # 提取基本信息
            h1 = soup.find('h1')
            if h1:
                vod["vod_name"] = h1.text.strip()
            
            # 尝试多种图片选择器
            pic_img = soup.select_one('.module-item-pic img')
            if pic_img:
                vod["vod_pic"] = pic_img.get('data-original', '') or pic_img.get('src', '')
            
            desc_div = soup.select_one('.module-info-introduction-content')
            if desc_div:
                vod["vod_content"] = desc_div.text.strip()
            
            # 提取演员和导演
            actor_p = soup.select_one('.module-info-info a')
            if actor_p:
                vod["vod_actor"] = actor_p.text.strip()

            # 提取播放列表 - 使用更通用的选择器
            play_froms = []
            play_urls_map = {}
            
            # 获取所有播放源标签
            tab_items = soup.select('.module-tab-items .module-tab-item span')
            if not tab_items:
                tab_items = soup.select('.module-tab-items .module-tab-item')
            
            # 获取所有播放列表容器
            list_containers = soup.select('.module-list.sort-list.tab-list.his-tab-list')
            
            print(f"  播放源标签数: {len(tab_items)}")
            print(f"  播放列表容器数: {len(list_containers)}")
            
            for i, tab in enumerate(tab_items):
                tab_text = tab.text.strip() if tab else f"线路{i+1}"
                if not tab_text or tab_text == '\n':
                    continue
                play_froms.append(tab_text)
                
                if i < len(list_containers):
                    container = list_containers[i]
                    episodes = []
                    links = container.select('.module-play-list-link')
                    for link in links[:100]:
                        ep_href = link.get('href', '')
                        ep_name = link.text.strip()
                        if ep_href and ep_name:
                            episodes.append(f"{ep_name}${ep_href}")
                    if episodes:
                        play_urls_map[tab_text] = '#'.join(episodes)
                    print(f"  {tab_text}: {len(episodes)} 集")

            vod["vod_play_from"] = '$$$'.join(play_froms) if play_froms else "wbbf"
            vod["vod_play_url"] = '$$$'.join([play_urls_map.get(pf, "") for pf in play_froms]) if play_froms else ""
            
            if not play_froms:
                vod["vod_play_from"] = "wbbf"
                match = re.search(r'/detail/(\d+)\.html', vid)
                vod["vod_play_url"] = f"第1集$/vplay/{match.group(1)}-1-1.html" if match else "暂无播放地址"
            
            print(f"  vod_name: {vod['vod_name']}")
            print(f"  vod_pic: {vod['vod_pic'][:60]}..." if vod['vod_pic'] else "  vod_pic: (空)")
            result["list"] = [vod]
        except Exception as e:
            print(f"detailContent error: {e}")
            import traceback
            traceback.print_exc()
            result["list"] = []
        return result

    def searchContent(self, key, quick, pg="1"):
        print(f"搜索关键词: {key}, 页码: {pg}")
        result = {}
        videos = []
        try:
            pg_str = str(pg) if pg and int(pg) > 1 else ''
            # 搜索 URL 格式: /search/关键词----------页码---.html
            search_url = f"{self.host}/search/{urllib.parse.quote(key)}----------{pg_str}---.html"
            print(f"  搜索URL: {search_url}")
            print(f"搜索URL: {search_url}")
            rsp = self.fetch(search_url, headers=self.header())
            soup = BeautifulSoup(rsp.text, 'html.parser')
            items = soup.select('.module-card-items .module-card-item')
            for item in items:
                poster_link = item.select_one('.module-card-item-poster')
                if not poster_link:
                    continue
                href = poster_link.get('href', '')
                title_tag = item.select_one('.module-card-item-title strong')
                title = title_tag.text.strip() if title_tag else ''
                img = item.select_one('.module-item-pic img')
                pic_url = img.get('data-original', '') or img.get('src', '') if img else ''
                note = item.select_one('.module-item-note')
                remark = note.text.strip() if note else ''
                if title and href:
                    videos.append({"vod_id": href, "vod_name": title, "vod_pic": self.build_full_url(pic_url), "vod_remarks": remark})
            result["list"] = videos
            result["page"] = int(pg) if pg else 1
            result["pagecount"] = 1
            result["limit"] = len(videos)
            result["total"] = len(videos)
        except Exception as e:
            print(f"搜索错误: {e}")
            result = {"list": [], "pagecount": 1, "page": 1, "limit": 0, "total": 0}
        return result

    def playerContent(self, flag, id, vipFlags=None):
        result = {}
        try:
            play_url = id
            print(f"播放请求 - ID: {play_url}, Flag: {flag}")

            if '$' in play_url:
                parts = play_url.split('$', 1)
                play_page_url = parts[1]
            else:
                play_page_url = play_url

            if not self.is_video_url(play_page_url):
                extract_result = self._extract_video_url(play_page_url)
                encrypt_url = extract_result.get("encrypt_url", "")
                full_play_page_url = extract_result.get("play_page_url", "")
                encrypt_flag = extract_result.get("encrypt", 0)

                print(f"extract encrypt_url: {encrypt_url[:60]}..." if encrypt_url else "No encrypt_url")
                print(f"extract play_page_url: {full_play_page_url}")
                print(f"extract encrypt flag: {encrypt_flag}")

                if encrypt_url:
                    decrypted_url = self._decryptAndPlay(encrypt_url, encrypt_flag, full_play_page_url)
                    if decrypted_url and self.is_video_url(decrypted_url):
                        result["parse"] = 0
                        result["playUrl"] = 0
                        result["url"] = decrypted_url
                        result["header"] = self.videoHeader()
                        print(f"播放成功(解密): {decrypted_url[:80]}...")
                    else:
                        result["parse"] = 1
                        result["playUrl"] = self.playurl
                        result["url"] = encrypt_url
                        result["header"] = self.videoHeader()
                        print(f"播放(使用解析器): playUrl={self.playurl}, url={encrypt_url[:60]}...")
                else:
                    result["parse"] = 1
                    result["playUrl"] = 0
                    result["url"] = full_play_page_url if full_play_page_url else play_page_url
                    result["header"] = self.videoHeader()
            else:
                result["parse"] = 0
                result["playUrl"] = 0
                result["url"] = play_page_url
                result["header"] = self.videoHeader()

            if vipFlags and flag in vipFlags:
                result["flag"] = flag
        except Exception as e:
            print(f"playerContent error: {e}")
            import traceback
            traceback.print_exc()
            result = {"parse": 1, "playUrl": 0, "url": id if id else "", "header": self.videoHeader()}
        return result

    def is_video_url(self, url):
        if not url:
            return False
        video_exts = ['.m3u8', '.mp4', '.flv', '.avi', '.mkv', '.wmv', '.mov']
        return any(ext in url.lower() for ext in video_exts)

    def _extract_video_url(self, play_page_url):
        result = {"encrypt_url": "", "play_page_url": "", "encrypt": 0}
        try:
            full_url = self.build_full_url(play_page_url)
            result["play_page_url"] = full_url
            print(f"访问播放页: {full_url}")
            rsp = self.fetch(full_url, headers=self.header())

            # 使用大括号计数法提取 JSON
            pos = rsp.text.find('player_aaaa')
            if pos == -1:
                print("未找到 player_aaaa")
                return result

            eq_pos = rsp.text.find('=', pos)
            brace_pos = rsp.text.find('{', eq_pos if eq_pos != -1 else pos)
            if brace_pos == -1:
                print("未找到 { 符号")
                return result

            start = brace_pos
            depth = 0
            i = brace_pos
            in_string = False
            escape = False

            while i < len(rsp.text):
                char = rsp.text[i]
                if escape:
                    escape = False
                    i += 1
                    continue
                if char == '\\':
                    escape = True
                    i += 1
                    continue
                if char == '"' and not escape:
                    in_string = not in_string
                if not in_string:
                    if char == '{':
                        depth += 1
                    elif char == '}':
                        depth -= 1
                        if depth == 0:
                            player_json = rsp.text[start:i+1]
                            break
                i += 1
            else:
                print("未找到匹配的 } 符号")
                return result

            print(f"提取的JSON长度: {len(player_json)}")
            player_json_clean = player_json.replace('\\"', '"').replace('\\/', '/')
            player_data = json.loads(player_json_clean)

            url_value = player_data.get('url', '')
            encrypt = player_data.get('encrypt', 0)
            print(f"player_aaaa url: {url_value[:60]}...")
            print(f"player_aaaa encrypt: {encrypt}")

            result["encrypt_url"] = url_value
            result["encrypt"] = encrypt
            return result
        except Exception as e:
            print(f"提取视频URL错误: {e}")
            import traceback
            traceback.print_exc()
        return result

    def _decryptAndPlay(self, url_value, encrypt=0, play_page_url=""):
        # 尝试两个可能的解析器域名
        hosts_to_try = [
            "https://xn--qvr2v.850088.xyz",
        ]
        
        for ph in hosts_to_try:
            try:
                api_url = f"{ph}/player/api.php"
                params = self.buildApiParams(url_value, play_page_url)
                print(f"API请求: {api_url}")

                req_headers = self.header().copy()
                req_headers['Accept'] = 'application/json, text/javascript, */*; q=0.01'
                req_headers['Origin'] = ph
                req_headers['Sec-Fetch-Site'] = 'same-origin'
                req_headers['Sec-Fetch-Mode'] = 'cors'
                req_headers['Sec-Fetch-Storage-Access'] = 'active'
                req_headers['Priority'] = 'u=1, i'

                rsp = self.post(api_url, data=params, headers=req_headers)
                print(f"API状态码: {rsp.status_code}")
                print(f"API响应: {rsp.text[:300]}")

                if rsp and rsp.status_code == 200:
                    data = rsp.json()
                    print(f"API响应JSON: {json.dumps(data, ensure_ascii=False)[:300]}")
                    if data.get('code') == 200:
                        encrypted_url = data.get('url', '')
                        aes_key = data.get('aes_key', '')
                        aes_iv = data.get('aes_iv', '')
                        if encrypted_url and aes_key and aes_iv:
                            real_url = self.decryptVideoUrl(encrypted_url, aes_key, aes_iv, url_value)
                            print(f"解密结果: {real_url[:100]}..." if real_url else "解密失败")
                            # 更新 playerHost 为成功的域名
                            self.playerHost = ph
                            self.playurl = f"{ph}/player/?url="
                            return real_url
                print(f"域名 {ph} 解密失败，尝试下一个...")
            except Exception as e:
                print(f"域名 {ph} 请求失败: {e}")
                continue
        
        return None

    def liveContent(self, url):
        try:
            rsp = self.fetch(url, headers=self.header())
            return rsp.text
        except Exception as e:
            print(f"liveContent error: {e}")
            return ""

    def localProxy(self, param):
        try:
            url = param.get('url', '') if isinstance(param, dict) else ''
            if not url:
                return [400, "text/plain", b"Missing url parameter"]
            rsp = self.fetch(url, headers=self.header())
            content_type = rsp.headers.get('Content-Type', 'application/octet-stream')
            return [rsp.status_code, content_type, rsp.content]
        except Exception as e:
            print(f"localProxy error: {e}")
            return [500, "text/plain", f"Proxy error: {str(e)}".encode('utf-8')]

    def action(self, action):
        result = {}
        try:
            print(f"action called with: {action}")
            result["msg"] = "action received"
        except Exception as e:
            result["msg"] = str(e)
        return result

    def isVideoFormat(self, url):
        if not url:
            return False
        video_exts = ['.mp4', '.m3u8', '.flv', '.avi', '.mkv', '.wmv', '.mov']
        return any(ext in url.lower() for ext in video_exts)

    def manualVideoCheck(self):
        return False

    def destroy(self):
        pass