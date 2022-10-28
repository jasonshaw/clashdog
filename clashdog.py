from scriptcat import ParseCIDR

# 标准库
import threading
import asyncio
import logging
import argparse
import sys
import os
import re
import ast
import errno

from urllib.parse import urlparse, urlunparse, unquote
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


class BaseInsert:
    def onLoopInit(self):
        pass

    async def load(self):
        self.policies = {"DIRECT": False, "REJECT": False}  # policy: disable-udp

        # 读取配置
        with open(abspath(self.configPath)) as stream:
            config = yaml.load(stream, Loader=yaml.Loader)

            for p in config.get("proxies", []):
                p = DictObj(p)
                self.policies[p.name] = not p.udp if "udp" in p else True

            for p in config.get("proxy-groups", []):
                p = DictObj(p)
                self.policies[p.name] = p.disable_udp if "disable-udp" in p else False

            host = config.get("external-controller", f":{self.port}")
            self.port = urlparse(f"http://{host}").port

        logging.debug(self.policies)

        # 发送请求
        resp = await asyncio.get_event_loop().run_in_executor(None, get, self.url)

        self.encoding = resp.encoding
        self.text = resp.text
        self.headers = resp.headers

    async def save(self):
        script = astor.parse_file("scriptcat.py")
        script = ast.fix_missing_locations(AddRules(self).visit(script))
        script = ast.fix_missing_locations(RewriteRules().visit(script))

        with open(
            fileRotate(self.rotateFileName, self.fileMaxRotate),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as stream:
            stream.write(astor.to_source(script))
            stream.write(f"\n'''\n{astor.dump_tree(script)}\n'''\n")

    async def wait(self):
        pass

    async def loop(self, currentInsert, argv):
        self.filter = currentInsert.filter
        self.url = currentInsert.url

        self.defaultPolicy = argv.default_policy
        self.rotateFileName = argv.filename
        self.fileMaxRotate = argv.file_max_rotate
        self.port = argv.port
        self.configPath = argv.config_file

        # 计算实际下标
        index = argv.insert.index(currentInsert)
        self.push = sum(
            [1 for x in argv.insert[index + 1 :] if x.push == "front"],
            index if currentInsert.push == "back" else 0,
        )

        self.onLoopInit()

        while True:
            await self.load()
            await self.save()

            # 重载配置
            logging.info("Reload configuration")
            # 本地速度快不需要异步
            # clash本身支持软链接
            put(
                f"http://127.0.0.1:{self.port}/configs?force=true",
                json={"path": self.configPath},
            )

            await self.wait()


class HTTPInsert(BaseInsert):
    def __fileName(self):
        return re.findall('filename="(.+)"', self.headers["Content-Disposition"])[0]

    def __interval(self):
        return int(self.headers["profile-update-interval"])

    async def load(self):
        await super().load()

        self.fileName = self.__fileName()
        self.interval = self.__interval()

    async def save(self):
        await super().save()

        with open(self.fileName, "w", encoding=self.encoding, newline="\n") as stream:
            stream.write(self.text)

        logging.info(f"saved file to {abspath(self.fileName)}")

    async def wait(self):
        logging.info(f"{self.fileName} next update in {self.interval} hours")
        await asyncio.sleep(self.interval * 3600)


class FileInsert(BaseInsert, FileSystemEventHandler):
    def onLoopInit(self):
        self.__event = asyncio.Event()
        self.__lock = threading.Lock()

        path_parts = [unquote(x) for x in self.url.path.split("/")]
        while path_parts and not path_parts[0]:
            path_parts.pop(0)
        if any(os.sep in p for p in path_parts):
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT))
        self.fileName = "path_parts"

        obs = Observer()
        obs.schedule(self, self.fileName)
        obs.start()
        logging.debug(obs._watches)

    async def wait(self):
        with self.__lock:
            await self.__event.wait()
            self.__event.clear()

    def on_modified(self, event):
        logging.debug(event)
        with self.__lock:
            self.__event.set()


class AddRules(ast.NodeTransformer):
    _Rules = []

    @staticmethod
    def __toAstLiterals(data):
        if isinstance(data, list):
            return AddRules.__toAstList(data)
        if isinstance(data, dict):
            return AddRules.__toAstDict(data)
        return ast.Constant(data)

    @staticmethod
    def __toAstList(data):
        return ast.List([AddRules.__toAstLiterals(x) for x in data])

    @staticmethod
    def __toAstDict(data):
        keys = []
        vals = []
        for k, v in data.items():
            keys.append(AddRules.__toAstLiterals(k))
            vals.append(AddRules.__toAstLiterals(v))
        return ast.Dict(keys, vals)

    @classmethod
    def __toAstRules(cls):
        return cls.__toAstLiterals(cls._Rules)

    def __init__(self, insert):
        super().__init__()

        assert len(AddRules._Rules) > insert.push, "insufficient list space"
        self.filter = set(insert.filter)  # complexity -> Average: O(1), Worst: O(n)

        data = yaml.load(insert.text, Loader=yaml.Loader)["rules"]

        # 过滤规则
        if False:
            pass
        elif "off" in self.filter:
            pass
        elif "all" in self.filter:
            data = []
        else:
            # TODO: same
            data = [
                x
                for x in data
                if ("geoip" in self.filter and "GEOIP" not in x)
                or ("match" in self.filter and "MATCH" not in x)
            ]

        # 解析规则
        for i, e in enumerate(data):
            rule = e.split(",")
            rule.insert(0, e)  # original_rule_string

            # 创建 IPNet 对象
            if "IP-CIDR" in rule[1]:
                _, ipnet, err = ParseCIDR(rule[2])
                if err:
                    logging.error(f"illegal IP {err['Text']}")
                    continue
                rule[2] = ipnet

            j = 2 if rule[1] == "MATCH" else 3
            p = rule[j]

            # 替换不存在的 Policy
            if p not in insert.policies:
                logging.warning(f"loss policy {e}")
                rule[j] = p = insert.defaultPolicy

            # 填充 MATCH 中缺少的 Matcher，以便让 `rule` 的长度保持一致
            if j == 2:
                rule.insert(j, rule[j])

            # 确保 Option 始终存在，哪怕没有值
            if False:
                pass
            elif len(rule) == 5 and insert.policies[p] and "disable-udp" not in rule[4]:
                rule[4] += ";disable-udp"
            elif len(rule) == 4:
                rule.append("disable-udp" if insert.policies[p] else "")

            data[i] = rule

        AddRules._Rules[insert.push] = data

    def visit_Module(self, node):
        node.body.insert(
            0, ast.Assign([ast.Name("_RULES")], AddRules.__toAstRules(), None)
        )
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


async def main():
    logging.basicConfig(level=logging.DEBUG)

    argv = argvparse()
    aws = []
    for i in argv.insert:
        aws.append(
            (FileInsert() if i.url.scheme == "file" else HTTPInsert()).loop(i, argv)
        )
    AddRules._Rules = [None] * len(argv.insert)
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


def fileRotate(fileName, max):
    for i in range(max - 1 if max > 0 else 0, -1, -1):
        newpath = Path(f"{fileName}.{i}")
        oldpath = Path(f"{fileName}.{i-1}" if i else fileName)
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
        return s.get(
            urlunparse(url) if isinstance(url, tuple) and len(url) == 6 else url
        )


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
        help="The clashdog checks for the existence of rule-policies in config.yaml and uses default_policy when they do not exist.",
    )
    parser.add_argument(
        "-i",
        "--insert",
        action="append",
        required=True,
        help="merge rules in order",
        metavar="<Syntax>",
    )
    parser.add_argument(
        "-f",
        "--filename",
        default="rules.star",
        help="final generated script filename",
        metavar="rules.star",
    )
    parser.add_argument(
        "-r",
        "--file-max-rotate",
        default=3,
        type=int,
        help="max rotate file count",
        metavar=3,
    )
    parser.add_argument(
        "-p",
        "--port",
        default=9090,
        type=int,
        help="port for clash RESTful API",
        metavar=9090,
    )
    parser.add_argument(
        "-c",
        "--config-file",
        default="config.yaml",
        help="clash configuration file",
        metavar="config.yaml",
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
