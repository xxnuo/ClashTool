import urllib.request
from urllib.parse import unquote as url_decode
import os
import toml
import yaml
import base64
import re
import hashlib
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def parse_single_proxy(proxy_url) -> dict:
    """
    解析单个代理链接

    :param proxy_url: 代理链接
    :return: 解析结果
    """
    if '://' not in proxy_url: return {}
    params = {}
    for pair in proxy_url.split('?')[1].split('#')[0].split('&'):
        key, value = pair.split('=')
        if key == 'type' and value == 'tcp':
            params['tcp'] = 'true'
        else:
            params[key] = value

    result = {
        **params,
        "type": proxy_url.split(':')[0],
        "password": url_decode(proxy_url.split('://')[1].split('@')[0]),
        "server": proxy_url.split('@')[1].split(':')[0],
        "port": proxy_url.split('@')[1].split(':')[1].split('?')[0],
        "name": url_decode(proxy_url.split('#')[1])
    }
    return result


def cached_update(name: str, interval: int) -> bool:
    """
    根据更新间隔返回是否需要更新文件

    :param name: 文件名
    :param interval: 更新间隔
    :return: 是否需要更新文件
    """
    global cache_dir

    current_time = int(time.time())
    timelog_path = os.path.join(cache_dir, 'timestamp.toml')
    name_md5 = hashlib.md5(name.encode()).hexdigest()
    if os.path.exists(timelog_path):
        with open(timelog_path, 'r', encoding='utf-8') as f:
            full_timelog = toml.load(f)
            timelog = full_timelog['Timestamps']
        if name_md5 in timelog:
            previous_time = timelog[name_md5]
            if current_time - previous_time < interval:
                return False
    else:
        timelog = {}
    timelog[name_md5] = current_time
    with open(timelog_path, 'w', encoding='utf-8') as f:
        toml.dump(full_timelog, f)
    return True


def cached_download(url, headers=None, timeout=10, skippable=True,
                    force_update=False):
    """
    下载指定链接的文件，可以指定 UA ，可选保存为文件。返回content对象
    若下载失败返回 cache 的文件
    skippable 默认真，即下载失败且没有缓存的文件时跳过下载，返回 '';
    force_update 默认为假, 直接使用缓存过的文件；

    :param url: 下载链接
    :param headers: 请求头
    :param timeout: 超时时间
    :param skippable: 是否跳过下载
    :param force_update: 强制从url更新，下载失败后再读取本地缓存
    :return: 下载结果
    """
    global cache_dir
    global DEBUG
    res = ''
    url_md5 = hashlib.md5(url.encode()).hexdigest()
    save_path = os.path.join(cache_dir, url_md5)
    if headers is None:
        headers = {
            # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Cookie': 'cf_chl_2=39d7d3fcb9c8b38; cf_clearance=EYM249DP7vStoratrN6UHH6PgZgFAf.duaZnbOmj9mQ-1679479741-0-150',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'TE': 'trailers',
        }
    if force_update:
        req = urllib.request.Request(url, headers=headers)
        try:
            res = urllib.request.urlopen(req, timeout=timeout).read().decode()
        except Exception as e:
            # 下载失败
            print(f'err: {e}')
            print(f'err: {url_md5} 更新失败')
            if DEBUG: print(f'dbg: {url_md5} : {url}')
        else:
            # 下载成功
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(res)
            print(f'info: {url_md5} 文件已更新')
            if DEBUG: print(f'dbg: {url_md5} : {url}')
        finally:
            pass
            # 无论成功失败都要读取文件
    # 无论 force_update 与否，从本地读取文件
    try:
        print(f'info: {url_md5} 读取文件')
        if DEBUG: print(f'dbg: {url_md5}: {url}')
        res = open(save_path, 'r', encoding='utf-8').read()
    except Exception as e:
        print(f'err: {e}')
        print(f'err: {url} 缓存文件读取失败')
        if skippable:
            return res
        else:
            # 此时一般是 force_update=False，尝试一下更新文件，不使用缓存
            print(f'info: {url_md5} 尝试重新下载文件')
            res = cached_download(url, headers=headers, timeout=timeout, skippable=skippable,
                                  force_update=True)
            if res == '': er(f'err: {url} 下载失败', 5)
    return res


def er(msg, code=-1):
    """
    打印错误信息并退出程序

    :param msg: 错误信息
    :param code: 退出码
    """
    print(msg)
    # if code != 0:
    #     exit(code)


def read_clashbase(clash_base: dict) -> dict:
    """
    读取 Clash-Base 配置

    :param clash_base: Clash-Base 配置
    :return: Clash-Base 配置
    """
    global root_dir
    ret_clashbase = {}
    if 'type' not in clash_base:
        er('Profile.Clash-Base.type 属性缺失', 2)
        return {}
    if clash_base['type'] == 'file':
        if 'path' not in clash_base:
            er('Profile.Clash-Base.path 属性缺失', 2)
            return {}
        # 模板文件来源是本地文件
        with open(os.path.join(root_dir, clash_base['path']), 'r',
                  encoding='utf-8') as f:
            ret_clashbase = yaml.safe_load(f)
    elif clash_base['type'] == 'http':
        if 'url' not in clash_base:
            er('Profile.Clash-Base.url 属性缺失', 2)
            return {}
        # 模板文件来源是远程文件，直接更新
        res = cached_download(clash_base['url'], skippable=False)
        ret_clashbase = yaml.safe_load(res)
    else:
        er('Profile.Clash-Base.type 配置错误，可选：file http', 2)
        return {}
    return ret_clashbase


def read_proxies(proxy_providers: dict) -> list:
    """
    读取 Proxy-Provider 配置

    :param proxy_providers: Proxy-Provider 配置
    :return: 线路列表
    """
    global update_interval_proxy_provider
    ret_proxies = []
    # print(proxy_providers)
    # 根据 provider['type'] 的值分别处理，可能的取值是 proxy http http.clash
    for provider in proxy_providers:
        provider_type = provider['type']
        if provider_type == 'proxy':
            # 一条线路
            proxy_info = parse_single_proxy(provider['url'])
            if 'name' in provider: proxy_info['name'] = provider['name']
            ret_proxies.append(proxy_info)
        elif provider_type.startswith('http'):
            # 远程订阅：一组线路
            config = {}
            whether_update = cached_update(provider['url'], update_interval_proxy_provider)
            res = cached_download(provider['url'], force_update=whether_update)
            if res == '':
                er(f'Profile.Proxy-Provider.{provider["name"]} 获取失败，跳过', 0)
            if res.endswith('=') or (':' not in res):
                # base64 加密过的节点组
                res = base64.b64decode(res).decode()
                config['proxies'] = []
                for line in res.splitlines():
                    # 一条线路
                    proxy_info = parse_single_proxy(line)
                    config['proxies'].append(proxy_info)
            else:
                # clash 配置文件
                config = yaml.safe_load(res)

            if 'proxies' in config:
                for proxy in config['proxies']:
                    if 'filter' not in provider:
                        ret_proxies.append(proxy)
                    else:
                        if proxy_filter(proxy, provider['filter']):
                            ret_proxies.append(proxy)
                        else:
                            er(f'info: 排除节点：{proxy["name"]}', 0)

            # print(config['proxies'])
    return ret_proxies


def reg_filter(name_str: str, reg_str: str) -> bool:
    """
    正则表达式过滤器

    :param name_str: 待过滤字符串
    :param reg_str: 正则表达式
    :return: 是否匹配
    """
    return bool(re.search(reg_str, name_str))


def proxy_filter(proxy_info: dict, config_filter: dict) -> bool:
    """
    线路过滤器

    :param proxy_info: 线路信息
    :param config_filter: 过滤器配置
    :return: 是否匹配
    """
    exclude = '()'
    include = '()'
    if 'exclude' in config_filter: exclude = config_filter['exclude']
    if 'include' in config_filter: include = config_filter['include']
    return reg_filter(proxy_info['name'], f'^(?!.*{exclude}).*(?={include}).*$')


def read_proxy_groups(proxy_groups: dict, proxies_name: list) -> list:
    """
    读取 Proxy-Groups 配置

    :param proxy_groups: Proxy-Groups 配置
    :param proxies_name: 线路名称列表
    :return: 策略集列表
    """
    global default_urltest_interval
    ret_proxy_groups = []
    for group in proxy_groups:
        group_processed = {}
        if 'proxies' not in group:
            er(f'Profile.Proxy-Groups.{group["name"]}内没有策略', 4)
            return []
        if 'type' in group:
            if group['type'] != 'select' and ('interval' not in group):
                er(f'warn: Profile.Proxy-Groups.{group["name"]}内未设置更新时间间隔，使用 ClashTool.default.url-test-interval 配置值或默认值 300',
                   0)
                group['interval'] = default_urltest_interval
        else:
            er(f'Profile.Proxy-Groups.{group["name"]}内没有策略', 4)
            return []

        group_processed = group
        raw_proxies = group_processed['proxies']
        cooked_proxies = []
        for i in range(len(raw_proxies)):
            if raw_proxies[i].startswith('{') and raw_proxies[i].endswith('}'):
                # 非策略名，匹配节点并加入
                strategy = raw_proxies[i][1:-1]
                if strategy == 'ALL':
                    # 展开并插入 proxies_name 到这个位置
                    cooked_proxies.extend(proxies_name)
                else:
                    # {正则表达式匹配线路名称}
                    for proxy_name in proxies_name:
                        # 遍历线路
                        if reg_filter(proxy_name, strategy):
                            # 匹配通过，添加
                            cooked_proxies.append(proxy_name)
                        else:
                            # 匹配不通过
                            pass
            else:
                # 普通策略名，直接添加
                cooked_proxies.append(raw_proxies[i])

        group_processed['proxies'] = cooked_proxies
        ret_proxy_groups.append(group_processed)
        # 处理完其中一个策略组
    pass
    # 处理完所有策略组
    return ret_proxy_groups


def read_rules(rules: dict) -> list:
    """
    读取 Rules 配置 (不含远程配置，手动编写规则，添加到 Rules 开头)

    :param rules: Rules 配置
    :return: 规则列表
    """
    ret_rule = []
    for rule in rules:
        # 单个规则组
        rule_list = rules_filter(rule['ruleset'], rule['group'])
        ret_rule.extend(rule_list)
    return ret_rule


def rules_filter(rule_list: list, group_name: str) -> list:
    global update_interval_rules
    ret_rule = []
    for rule in rule_list:
        rule = rule.strip()
        if rule.startswith('http'):
            # 远程策略集,进行递归解析
            whether_update = cached_update(rule, update_interval_rules)
            remote_rules_str = cached_download(rule, skippable=False,
                                               force_update=whether_update)
            remote_rules = remote_rules_str.splitlines()
            for line in remote_rules:
                # 不需要再设置忽略注释，函数内部会解析
                ret_rule_str = rule_single_filter(line, group_name)
                if ret_rule_str != '':
                    ret_rule.append(ret_rule_str)
        else:
            # 普通策略，直接解析
            ret_rule_str = rule_single_filter(rule, group_name)
            if ret_rule_str != '':
                ret_rule.append(ret_rule_str)

    return ret_rule


def rule_single_filter(rule_str: str, group_name: str) -> str:
    """
    单条规则过滤器

    :param rule_str: 规则字符串
    :param group_name: 所属策略集名称
    :return: 规则字符串
    """
    ret_rule = ''
    rule_str = rule_str.strip()

    CLASH_SUPPORT_KEYWORDS: list[str] = [
        'DOMAIN', 'IP-CIDR', 'SRC', 'DST', 'PROCESS-NAME', 'MATCH', 'GEOIP',
        # 特殊规则
        '[]GEOIP', '[]FINAL',
    ]

    if rule_str == '' or rule_str.startswith('#'):
        # 忽略空行和注释
        pass
    elif not any(rule_str.startswith(keyword) for keyword in CLASH_SUPPORT_KEYWORDS):
        # 不以 CLASH_SUPPORT_KEYWORDS 中的任意一个元素开头
        pass
    elif rule_str.startswith('[]'):
        # 保留地址策略
        if rule_str.startswith('[]GEOIP'):
            _reserve_rule = rule_str.split(',')
            _reserve_rule[0] = 'GEOIP'
            _reserve_rule.insert(2, group_name)
            ret_rule = ','.join(_reserve_rule)
        elif rule_str == '[]FINAL':
            # 特殊策略，一般放在最后
            ret_rule = f'MATCH,{group_name}'
        pass

    # 其他普通策略
    elif rule_str.endswith('no-resolve'):
        # 以 no-resolve 结尾的需要变为 group_name,no-resolve
        ret_rule = f'{rule_str[:-11]},{group_name},no-resolve'

    else:
        # 更加普通的策略
        ret_rule = f'{rule_str},{group_name}'

    # 若策略未被解析返回空字符串
    return ret_rule


def reload() -> bool:
    """
    重新加载配置文件

    :return: 是否成功
    """
    global root_dir
    global profile

    reload_done = False
    profile = read_profile(profile_path)
    # 刷新配置文件完成

    output = read_clashbase(profile.get('Clash-Base') or profile.get('clash-base'))
    if not output:
        return False
    # 模板文件读取完成

    all_proxies = read_proxies(profile.get('Proxy-Provider') or profile.get('proxy-provider'))
    if not len(all_proxies):
        er('无线路，程序退出', 1)
        return False
    output['proxies'] = all_proxies
    # 线路加载完成

    all_proxy_groups = read_proxy_groups(profile.get('Proxy-Groups') or profile.get('proxy-groups'),
                                         [proxy['name'] for proxy in all_proxies])
    if not all_proxy_groups:
        return False
    output['proxy-groups'] = all_proxy_groups
    # 策略集加载完成

    all_rules = read_rules(profile.get('Rules') or profile.get('rules'))
    if not all_rules:
        return False
    output['rules'] = all_rules
    # 规则集加载完成

    with open(os.path.join(root_dir, 'Output.yaml'), 'w', encoding='utf-8') as fs:
        yaml.dump(output, fs, allow_unicode=True)
        reload_done = True
    # 输出配置文件完成
    print(f'info: 配置文件已输出')

    return reload_done


def read_profile(config_path: str) -> dict:
    """
    读取指定位置的 toml 配置文件

    :param config_path: 配置文件路径
    :return: 配置文件内容
    """
    global profile
    global update_interval_rules
    global update_interval_proxy_provider
    global default_urltest_interval

    with open(config_path, 'r', encoding='utf-8') as f:
        profile = toml.load(f)
    update_interval_rules = profile.get('ClashTool', {}) \
                                .get('update-interval', {}) \
                                .get('Rules', 0) or 86400
    update_interval_proxy_provider = profile.get('ClashTool', {}) \
                                         .get('update-interval', {}) \
                                         .get('Proxy-Provider', 0) or 5
    default_urltest_interval = profile.get('ClashTool', {}) \
                                   .get('default', {}) \
                                   .get('url-test-interval', 0) or 43200

    return profile


class ClashToolServer(BaseHTTPRequestHandler):
    global profile

    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        query_dict = urllib.parse.parse_qs(query)
        if self.path.startswith('/Output.yaml') \
                and 'token' in query_dict \
                and query_dict['token'][0] == profile.get('ClashTool', {}) \
                .get('web', {}).get('token', '') \
                and reload():
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            with open(os.path.join(root_dir, 'Output.yaml'), 'rb') as f:
                self.wfile.write(f.read())

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"404 Not Found")


def run_server():
    global profile

    web_host = profile.get('ClashTool', {}).get('web', {}).get('host', '127.0.0.1')
    web_port = profile.get('ClashTool', {}).get('web', {}).get('port', 50510)
    web_token = profile.get('ClashTool', {}).get('web', {}).get('token', 'ClashTool')
    server_address = (web_host, web_port)
    httpd = HTTPServer(server_address, ClashToolServer)
    print(f'Started server on: http://{web_host}:{web_port}/Output.yaml?token={web_token}')
    httpd.serve_forever()


if __name__ == '__main__':
    DEBUG = True

    profile_path = r'./Profile.toml'
    root_dir = os.path.dirname(os.path.abspath(profile_path))
    cache_dir = os.path.join(root_dir, 'cache')
    if not os.path.exists(cache_dir): os.makedirs(cache_dir)
    # 缓存文件夹创建完成

    # 准备一下全局变量
    profile = []
    update_interval_rules = update_interval_proxy_provider = default_urltest_interval = 0
    # 读取一些配置进全局变量
    read_profile(profile_path)

    # 初始化配置
    # reload()

    web_enable = profile.get('ClashTool', {}).get('web', {}).get('enable', True)
    if web_enable:
        # 目前只处理自己使用的情况，起一个简单的 HTTP 服务即可
        run_server()
    else:
        reload()
