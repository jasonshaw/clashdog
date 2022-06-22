import yaml
import sys
import re
import requests
import traceback
import logging
from requests import get, put
from shutil import copyfileobj
from script import ParseCIDR
from os import path
from time import sleep

def save_as_yaml(req):
  filename = re.findall('filename="(.+)"', req.headers['Content-Disposition'])[0].lower()
  with open('./{0}.yaml'.format(filename), 'w', encoding = req.encoding, newline = '\n') as stream:
    stream.write(req.text)

def save_as_rule(req, _Policies):
  with open('./config.yaml') as stream:
    groups = yaml.load(stream, Loader = yaml.Loader)['proxy-groups']
    for i in range(len(groups)):
      groups[i] = groups[i]['name']
    groups.insert(0, 'DIRECT')
    groups.insert(1, 'REJECT')

  with open('./script.rules.py', 'w', encoding = 'utf-8', newline = '\n') as stream:
    # 解析规则
    stream.write('rules = [\n')
    rules = yaml.load(req.text, Loader = yaml.Loader)['rules']
    for i, e in enumerate(rules):
      rule = e.split(',')

      if 'IP-CIDR' in rule[0]:
        _, ipnet, err = ParseCIDR(rule[1])
        if err:
          logging.error('非法IP %s', e)
          continue
        rule[1] = [ipnet, rule[1]]

      p = 2 if len(rule) >= 3 else 1
      if rule[p] not in groups:
        logging.warning('缺少Policies %s', e)
        rule[p] = _Policies

      rule.append(e)
      stream.write('{0}{1}\n'.format(rule, ',' if i + 1 < len(rules) else '\n]'))

    # 默认策略
    stream.write('_Policies = "{0}"\n'.format(_Policies))

    # 拼接脚本
    with open('./script.py') as fsrc:
      stream.write('\n"""\n{0}\n"""\n'.format(fsrc.name))
      copyfileobj(fsrc, stream)

  # 重新加载配置文件
  put('http://127.0.0.1:9090/configs?force=true', json = {'path': path.abspath('./config.yaml')})

def run(argv):
  logging.basicConfig(level = logging.INFO)
  i = 0
  while True:
    try:
      req = get(argv[2])
    except requests.Timeout:
      sleep(10 * i)
      i += 1
      traceback.print_exc()
      logging.info('第%s次重试', i)
      continue
    else:
      i = 0

    save_as_yaml(req)
    save_as_rule(req, argv[1])

    h = int(req.headers['profile-update-interval'])
    sleep(h * 3600)

if __name__ == '__main__':
  run(sys.argv)
