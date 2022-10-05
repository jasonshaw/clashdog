from script import ParseCIDR

# 标准库
import asyncio
import logging
import argparse
import sys
import os
import re

from urllib.parse import urlparse
from shutil import copyfileobj

# 第三方库
import requests
import yaml

from requests import put
from requests.adapters import HTTPAdapter
from requests_file import FileAdapter
from urllib3.util.retry import Retry


def parse_rule(rules, Policies, _Policies):
    for i, e in enumerate(rules):
        rule = e.split(",")

        if "IP-CIDR" in rule[0]:
            _, ipnet, err = ParseCIDR(rule[1])
            if err:
                logging.error("Illegal IP %s", e)
                continue
            rule[1] = [ipnet, rule[1]]

        p = 2 if len(rule) >= 3 else 1
        if rule[p] not in Policies:
            logging.warning("Missing Policies %s", e)
            rule[p] = _Policies

        rule.append(e)
        rules[i] = rule


def merge_rules(e, resp):
    ee = [None] * len(e)
    for i, v in enumerate(e):
        ee[i] = argparse.Namespace(data=filespt_get(v.url), filter=v.filter)
        if urlparse(v.url).scheme != "file":
            save_as_yaml(ee[i].data)
    ee.append(argparse.Namespace(data=resp, filter="off"))

    rules = []
    for i, v in enumerate(ee):
        if v.filter == "all":
            ee[i] = None
            continue
        v.data = yaml.load(v.data.text, Loader=yaml.Loader)["rules"]
        if "geoip" in v.filter:
            v.data = [i for i in v.data if "GEOIP" not in i]
        if "match" in v.filter:
            v.data = [i for i in v.data if "MATCH" not in i]
        rules.extend(v.data)
    return rules


def save_as_skpy(resp, _Policies, e):

    with open("./script.rules.py", "w", encoding="utf-8", newline="\n") as stream:
        # 解析规则
        stream.write("rules = [\n")
        rules = merge_rules(e, resp)
        parse_rule(rules, Policies, _Policies)
        for i, r in enumerate(rules):
            stream.write("{0}{1}\n".format(r, "," if i + 1 < len(rules) else "\n]"))

        # 默认策略
        stream.write('_Policies = "{0}"\n'.format(_Policies))

        # 拼接脚本
        with open("./script.py") as fsrc:
            stream.write('\n"""\n{0}\n"""\n'.format(fsrc.name))
            copyfileobj(fsrc, stream)


async def run(currentInsert, defaultPolicy):
    while True:
        resp = await asyncio.get_event_loop().run_in_executor(
            None, get, currentInsert.url
        )

        filename = re.findall('filename="(.+)"', resp.headers["Content-Disposition"])[0]
        interval = int(resp.headers["profile-update-interval"])

        policies = {"DIRECT": False, "REJECT": False}  # policy: disable-udp

        # 保存文件
        with open(
            abspath(filename), "w", encoding=resp.encoding, newline="\n"
        ) as stream:
            stream.write(resp.text)
            logging.info(f"Saved file to {stream.name}")

        # 读取配置
        with open(abspath("config.yaml")) as stream:
            config = yaml.load(stream, Loader=yaml.Loader)

            for p in config.get("proxies", []):
                p = DictObj(p)
                policies[p.name] = not p.udp if "udp" in p else True

            for p in config.get("proxy-groups", []):
                p = DictObj(p)
                policies[p.name] = p.disable_udp if "disable-udp" in p else False

        with open(
            abspath("script.0.py"), "w", encoding="utf-8", newline="\n"
        ) as stream:
            pass

        # 重载配置，本地速度快不需要异步
        logging.info("Reload configuration")
        put(
            "http://127.0.0.1:9090/configs?force=true",
            json={"path": abspath("config.yaml")},
        )

        logging.info(f"{filename} next update in {interval} hours")
        await asyncio.sleep(interval * 3600)


async def main():
    logging.basicConfig(level=logging.INFO)

    argv = argvparse()
    aws = []
    for i in argv.insert:
        aws.append(run(i, argv.default_policy))
    await asyncio.gather(*aws)


class DictObj(dict):
    def __new__(cls, d):
        return super().__new__(cls) if isinstance(d, dict) else d

    def __init__(self, d):
        for k, v in d.items():
            v = DictObj(v)
            if "-" in k:
                self[k.replace("-", "_")] = v
            self[k] = v

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__


def abspath(path):
    path = os.path.abspath(path)
    return os.readlink(path) if os.path.islink(path) else path


def get(url):
    adapter = HTTPAdapter(max_retries=Retry(connect=3, backoff_factor=10))

    with requests.Session() as s:
        s.mount("file://", FileAdapter())
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s.get(url)


def argvparse():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Clash subscription updater, supports the separation of rules and configuration files.

`--insert`: Syntax: [push={front,back},filter={off,all,geoip,match,same},]url=scheme:[//authority]/path[?query]
            Consists of multiple key-value pairs, separated by commas and each consisting of a `<key>=<value>` tuple.
            The order of the keys is not significant.
            The insertion position is determined by the subparameter `push` and
            is merged in the order of appearance of this optional parameter.

  * The default value of `push` is `back`, only the following are supported:
    front       |   Insert rules at beginning
    back        |   Add rules at the end
  * The `filter` of the rules, optional, support multi-select with `;` split, default is `off`, the following values are:
    off         |   No filter used, conflict with others.
    all         |   Exclude all rules, conflict with others.
    geoip       |   Exclude `GEOIP`
    match       |   Exclude `MATCH`
    same        |   Exclude identical rules
  * The `url` option is the clash subscription address, and you can also use the FILE scheme.
""",
    )
    parser.add_argument(
        "default_policy",
        help="The clashdog checks for the existence of rule-policies in `config.yaml` and uses `default_policy` when they do not exist",
    )
    parser.add_argument(
        "-i",
        "--insert",
        action="append",
        required=True,
        help="Merge rules in order",
        metavar="<Syntax>",
    )

    args = parser.parse_args()
    logging.debug(args)

    # 处理子参数
    if args.insert:
        parser = argparse.ArgumentParser(
            prog=f"{os.path.basename(sys.argv[0])} --insert", add_help=False
        )
        parser.add_argument("--push", default="back", choices=["front", "back"])
        parser.add_argument(
            "--filter",
            action="append",
            default=["off"],
            choices=["off", "all", "geoip", "match", "same"],
        )
        parser.add_argument("--url", required=True)

        for i, e in enumerate(args.insert):
            logging.debug(f"--insert {e}")

            f = lambda x: "filter" in x

            e = e.split(",")
            for j, s in enumerate(e):
                if f and f(s):
                    s = s.replace(";", " filter=").split(" ")
                    s = [x for x in s if x != "filter="]
                    if len(s) > 1 and ("filter=off" in s or "filter=all" in s):
                        raise argparse.ArgumentError(
                            None, f"{e[j]} has conflicting values"
                        )
                    e.extend(s[1:])
                    s = s[0]
                    f = False

                e[j] = f"--{s}"
            e = parser.parse_args(e)

            if not f:
                del e.filter[0]  # 移除default
            args.insert[i] = e

    logging.debug(args)
    return args


if __name__ == "__main__":
    asyncio.run(main())
