import sys
import re
import traceback
import logging
import argparse
import threading

import yaml
import requests

from script import ParseCIDR
from shutil import copyfileobj
from os import path
from urllib.parse import urlparse
from time import sleep
from threading import Timer

from requests import get, put
from requests.adapters import HTTPAdapter
from requests_file import FileAdapter
from urllib3.util.retry import Retry


def save_as_yaml(resp):
    filename = re.findall('filename="(.+)"', resp.headers["Content-Disposition"])[
        0
    ].lower()
    with open(
        "./{0}.yaml".format(filename), "w", encoding=resp.encoding, newline="\n"
    ) as stream:
        stream.write(resp.text)


# ['Type', 'Matcher', 'Policy', 'original_rule_string']
#
# ['Type', {IP, Mask}, {'Policy', }, 'Option', 'original_rule_string']
# ['Type', {IP, Mask}, 'Policy', 'original_rule_string']
#
# ['MATCH', 'Policy', 'original_rule_string']
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


def filespt_get(url):
    s = requests.Session()
    s.mount("file://", FileAdapter())

    retries = Retry(connect=3, backoff_factor=10)
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter)
    s.mount("https://", adapter)

    i = 0
    while True:
        try:
            resp = s.get(url)
        except requests.Timeout:
            sleep(10 * i)
            i += 1
            logging.warning(traceback.format_exc())
            logging.info("%sth retry", i)
        else:
            break

    assert resp.ok
    return resp


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
    # 获取 Policies 的名称，必须每次重新读取，以应对文件变动
    with open("./config.yaml") as stream:
        config = yaml.load(stream, Loader=yaml.Loader)
        Policies = config.get("proxy-groups", [])
        Policies.extend(config.get("proxies", []))
        for i in range(len(Policies)):
            Policies[i] = Policies[i]["name"]
        Policies.insert(0, "DIRECT")
        Policies.insert(1, "REJECT")

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

    # 重新加载配置文件
    put(
        "http://127.0.0.1:9090/configs?force=true",
        json={"path": path.abspath("./config.yaml")},
    )


def parse():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Clash subscription updater, supports the separation of rules and configuration files.

`--insert`: Syntax: [position={append,extend},filter={all,geoip-match,match,off},]url=scheme:[//authority]/path[?query]
            Consists of multiple key-value pairs, separated by commas and each consisting of a `<key>=<value>` tuple.
            The order of the keys is not significant.
            The insertion position is determined by the subparameter `position`
            and is merged in the order of appearance of this optional parameter.

  * The `position` where the `rules` needs to be inserted, default values is `append`, only the followings are supported:
    append       |  Add backwards
    extend       |  Add forward
  * The `filter` of the rules, optional, support multi-select with `;` split, default is `match`, the following values are:
    off          |  No filter used, conflict with others.
    all          |  Exclude all rules, conflict with others.
    geoip        |  Exclude `GEOIP`.
    match        |  Exclude `MATCH`.
    same         |  Exclude identical rules.
  * The `url` option is the clash subscription address, and you can also use the FILE scheme.
""",
    )
    parser.add_argument(
        "default_policy",
        help="""The clashdog checks for the existence of rule-policies in `config.yaml`
                and uses `default_policy` when they do not exist.""",
    )
    parser.add_argument("-i", "--insert", action="append", help="Merge rules by order.")

    args = parser.parse_args()
    if args.insert:
        parser = argparse.ArgumentParser(
            prog=f"{path.basename(sys.argv[0])} --insert", add_help=False
        )
        parser.add_argument(
            "--position", default="append", choices=["append", "extend"]
        )
        parser.add_argument(
            "--filter",
            default="match",
            choices=["all", "off", "geoip", "match", "same"],
        )
        parser.add_argument("--url", required=True)

        s = args.insert
        for i, v in enumerate(s):
            logging.debug(f"--insert {v}")
            v = v.split(",")
            for j, s in enumerate(v):
                v[j] = f"--{s}"
            s[i] = parser.parse_args(v)

    logging.debug(args)
    return args


def main():
    logging.basicConfig(level=logging.INFO)

    args = parse()

    while True:
        resp = filespt_get(args.url)

        save_as_yaml(resp)
        save_as_skpy(resp, args.default_policy, args.extend_front)

        h = int(resp.headers["profile-update-interval"])
        sleep(h * 3600)


if __name__ == "__main__":
    main()
