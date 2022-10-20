from scriptcat import ParseCIDR

# 标准库
import asyncio
import logging
import argparse
import sys
import os
import re
import ast

from urllib.parse import urlparse
from urllib.parse import urlunparse
from pathlib import Path

# 第三方库
import requests
import yaml
import astor

from requests import put
from requests.adapters import HTTPAdapter
from requests_file import FileAdapter
from urllib3.util.retry import Retry
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


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
        rules = merge_rules(e, resp)
        parse_rule(rules, Policies, _Policies)
        for i, r in enumerate(rules):
            stream.write("{0}{1}\n".format(r, "," if i + 1 < len(rules) else "\n]"))


class BaseRule:
    configYaml = "config.yaml"
    scriptcat = "scriptcat.py"

    async def load(self):
        self.policies = {"DIRECT": False, "REJECT": False}  # policy: disable-udp

        # 读取配置
        with open(abspath(BaseRule.configYaml)) as stream:
            config = yaml.load(stream, Loader=yaml.Loader)

            for p in config.get("proxies", []):
                p = DictObj(p)
                self.policies[p.name] = not p.udp if "udp" in p else True

            for p in config.get("proxy-groups", []):
                p = DictObj(p)
                self.policies[p.name] = p.disable_udp if "disable-udp" in p else False

        logging.debug(self.policies)

        # 发送请求
        resp = await asyncio.get_event_loop().run_in_executor(None, get, self.url)

        self.encoding = resp.encoding
        self.text = resp.text
        self.headers = resp.headers

    async def save(self):
        script = astor.parse_file(BaseRule.scriptcat)
        script = ast.fix_missing_locations(AddRules().visit(script))
        script = ast.fix_missing_locations(RewriteRules().visit(script))

        with open(
            fileRotate(self.rotate_filename, self.file_max_rotate),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as stream:
            stream.write(astor.dump_tree(script))
            stream.write(astor.to_source(script))

    async def wait(self):
        pass

    async def loop(self, currentInsert, argv):
        self.push = currentInsert.push
        self.filter = currentInsert.filter
        self.url = currentInsert.url

        self.rotate_filename = argv.filename
        self.file_max_rotate = argv.file_max_rotate
        self.port = argv.port

        self.index = argv.insert.index(currentInsert)

        while True:
            await self.load()
            await self.save()

            # 重载配置
            logging.info("Reload configuration")
            # 本地速度快不需要异步
            # clash本身支持软链接
            put(
                f"http://127.0.0.1:{self.port}/configs?force=true",
                json={"path": BaseRule.configYaml},
            )

            await self.wait()


class HTTPRule(BaseRule):
    def __filename(self):
        return re.findall('filename="(.+)"', self.headers["Content-Disposition"])[0]

    def __interval(self):
        return int(self.headers["profile-update-interval"])

    async def load(self):
        await super().load()

        self.filename = self.__filename()
        self.interval = self.__interval()

    async def save(self):
        await super().save()

        with open(self.filename, "w", encoding=self.encoding, newline="\n") as stream:
            stream.write(self.text)

        logging.info(f"Saved file to {abspath(self.filename)}")

    async def wait(self):
        logging.info(f"{self.filename} next update in {self.interval} hours")
        await asyncio.sleep(self.interval * 3600)


class FileRule(BaseRule, FileSystemEventHandler):
    async def wait(self):
        observer = Observer()
        observer.schedule(self, self.url.path)
        observer.start()
        observer.join()
        self.observer = observer

    def on_modified(self, event):
        logging.debug(event)
        self.observer.stop()


async def main():
    logging.basicConfig(level=logging.DEBUG)

    argv = argvparse()
    aws = []
    for i in argv.insert:
        rule = FileRule() if i.url.scheme == "file" else HTTPRule()
        aws.append(rule.loop(i, argv))
    await asyncio.gather(*aws)


class AddRules(ast.NodeTransformer):
    def __init__(self):
        super().__init__()

        self.__rules = []

    def visit_Module(self, node):
        node.body.insert(0, ast.Assign([ast.Name("_RULES")], ast.List([]), None))
        return node


class RewriteRules(ast.NodeTransformer):
    def visit_Assign(self, node):
        if not (
            len(node.targets) == 2
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "RULES"
        ):
            return node
        return ast.Assign(node.targets[:1], node.targets[1], node.type_comment)


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


def fileRotate(filename, max):
    for i in range(max - 1 if max > 0 else 0, -1, -1):
        newpath = Path(f"{filename}.{i}")
        oldpath = Path(f"{filename}.{i-1}" if i else filename)
        # remove the old file
        if newpath.exists() and newpath.is_file():
            os.remove(newpath)
        # change the new file to old file name
        if oldpath.exists() and oldpath.is_file():
            os.rename(oldpath, newpath)
    return oldpath


def abspath(path):
    path = os.path.abspath(path)
    return os.readlink(path) if os.path.islink(path) else path


def get(url):
    adapter = HTTPAdapter(max_retries=Retry(connect=3, backoff_factor=10))

    with requests.Session() as s:
        s.mount("file://", FileAdapter())
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s.get(url if isinstance(url, str) else urlunparse(url))


def argvparse():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Clash subscription updater, supports the separation of rules and configuration files.

`--insert`: Syntax: [push={front,back},filter={off,all,geoip,match,same},]url=scheme://[authority]/path[?query]
            Consists of multiple key-value pairs, separated by commas and each consisting of a `<key>=<value>` tuple.
            The order of the keys is not significant.
            The insertion position is determined by the subparameter `push` and
            is merged in the order of appearance of this optional parameter.

  * The default value of `push` is `back`, only the following are supported:
    front       |   Insert rules at beginning
    back        |   Add rules at the end
  * The `filter` of the rules, optional, support multi-select with `;` split, default is `off`, the following values are:
    off         |   No filter used, conflict with others
    all         |   Exclude all rules, conflict with others
    geoip       |   Exclude `GEOIP`
    match       |   Exclude `MATCH`
    same        |   Exclude identical rules
  * The `url` option is the clash subscription address, and you can also use the FILE scheme
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
    parser.add_argument(
        "-f",
        "--filename",
        default="rules.star",
        help="Final Generated script filename",
        metavar="rules.star",
    )
    parser.add_argument(
        "-r",
        "--file-max-rotate",
        default=10,
        type=int,
        help="Max rotate file count",
        metavar=10,
    )
    parser.add_argument(
        "-p",
        "--port",
        default=9090,
        type=int,
        help="Port for clash RESTful API",
        metavar=9090,
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
        parser.add_argument("--url", type=urlparse, required=True)

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
