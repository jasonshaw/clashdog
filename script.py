Separator = "/"

byte = lambda x=0: int(x) & 0xFF
uint = lambda x=0: int(x) & 0xFFFFFFFF

# Base returns the last element of path.
# Trailing path separators are removed before extracting the last element.
# If the path is empty, Base returns ".".
# If the path consists entirely of separators, Base returns a single separator.
#
# see: https://github.com/golang/go/blob/master/src/path/filepath/path.go
def Base(path):
    if path == "":
        return "."
    # Strip trailing slashes.
    for ignore in range(len(path)):
        if not (len(path) > 0 and Separator == path[len(path) - 1]):
            break
        path = path[0 : len(path) - 1]
    # Find the last element
    i = len(path) - 1
    for ignore in range(len(path)):
        if not (i >= 0 and Separator != path[i]):
            break
        i -= 1
    if i >= 0:
        path = path[i + 1 :]
    # If empty now, it had only slashes.
    if path == "":
        return Separator
    return path


# EqualFold reports whether s and t, interpreted as UTF-8 strings,
# are equal under simple Unicode case-folding, which is a more general
# form of case-insensitivity.
#
# see: https://github.com/golang/go/blob/master/src/strings/strings.go
def EqualFold(s, t):
    # TODO? Maybe it will work.
    return s.lower() == t.lower()


"""
Simple file i/o and string manipulation, to avoid
depending on strconv and bufio and strings.

see: https://github.com/golang/go/blob/master/src/net/parse.go
"""
# Bigger than we need, not too big to worry about overflow
big = 0xFFFFFF

# Decimal to integer.
# Returns number, characters consumed, success.
def dtoi(s):
    n = 0
    for i in range(len(s) + 1):
        if not (i < len(s) and "0" <= s[i] and s[i] <= "9"):
            break
        n = n * 10 + int(s[i])
        if n >= big:
            return big, i, False
    if i == 0:
        return 0, 0, False
    return n, i, True


# Hexadecimal to integer.
# Returns number, characters consumed, success.
def xtoi(s):
    n = 0
    for i in range(len(s) + 1):
        if not (i < len(s)):
            break
        if (
            False
            or ("0" <= s[i] and s[i] <= "9")
            or ("a" <= s[i] and s[i] <= "f")
            or ("A" <= s[i] and s[i] <= "F")
        ):
            n *= 16
            n += int(s[i], 16)
        else:
            break
        if n >= big:
            return 0, i, False
    if i == 0:
        return 0, i, False
    return n, i, True


"""
IP address manipulations

IPv4 addresses are 4 bytes; IPv6 addresses are 16 bytes.
An IPv4 address can be converted to an IPv6 address by
adding a canonical prefix (10 zeros, 2 0xFFs).
This library accepts either size of byte slice but always
returns 16-byte addresses.

see: https://github.com/golang/go/blob/master/src/net/ip.go
"""
nil = None

# IP address lengths (bytes).
IPv4len = 4
IPv6len = 16

# IPv4 returns the IP address (in 16-byte form) of the
# IPv4 address a.b.c.d.
def IPv4(a, b, c, d):
    p = list(v4InV6Prefix)
    p.extend([a, b, c, d])
    return p


v4InV6Prefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]

# CIDRMask returns an IPMask consisting of 'ones' 1 bits
# followed by 0s up to a total length of 'bits' bits.
# For a mask of this form, CIDRMask is the inverse of IPMask.Size.
def CIDRMask(ones, bits):
    if bits != 8 * IPv4len and bits != 8 * IPv6len:
        return nil
    if ones < 0 or ones > bits:
        return nil
    l = bits / 8
    m = [0] * l
    n = uint(ones)
    for i in range(l):
        if n >= 8:
            m[i] = 0xFF
            n -= 8
            continue
        m[i] = ~byte(0xFF >> n)
        n = 0
    return m


# IsPrivate reports whether ip is a private address, according to
# RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
def IsPrivate(ip):
    ip4 = To4(ip)
    if ip4 != nil:
        # Following RFC 1918, Section 3. Private Address Space which says:
        #   The Internet Assigned Numbers Authority (IANA) has reserved the
        #   following three blocks of the IP address space for private internets:
        #     10.0.0.0        -   10.255.255.255  (10/8 prefix)
        #     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
        #     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
        return (
            ip4[0] == 10
            or (ip4[0] == 172 and ip4[1] & 0xF0 == 16)
            or (ip4[0] == 192 and ip4[1] == 168)
        )
    # Following RFC 4193, Section 8. IANA Considerations which says:
    #   The IANA has assigned the FC00::/7 prefix to "Unique Local Unicast".
    return len(ip) == IPv6len and ip[0] & 0xFE == 0xFC


# Is p all zeros?
def isZeros(p):
    for i in range(len(p)):
        if p[i] != 0:
            return False
    return True


# To4 converts the IPv4 address ip to a 4-byte representation.
# If ip is not an IPv4 address, To4 returns nil.
def To4(ip):
    if len(ip) == IPv4len:
        return ip
    if len(ip) == IPv6len and isZeros(ip[0:10]) and ip[10] == 0xFF and ip[11] == 0xFF:
        return ip[12:16]
    return nil


def allFF(b):
    for c in b:
        if c != 0xFF:
            return False
    return True


# Mask returns the result of masking the IP address ip with mask.
def Mask(mask, ip):
    if len(mask) == IPv6len and len(ip) == IPv4len and allFF(mask[:12]):
        mask = mask[12:]
    if len(mask) == IPv4len and len(ip) == IPv6len and ip[:12] == v4InV6Prefix:
        ip = ip[12:]
    n = len(ip)
    if n != len(mask):
        return nil
    out = [0] * n
    for i in range(n):
        out[i] = ip[i] & mask[i]
    return out


def networkNumberAndMask(n):
    ip = n["IP"]
    ip = To4(ip)
    if ip == nil:
        ip = n["IP"]
        if len(ip) != IPv6len:
            return nil, nil
    m = n["Mask"]
    l = len(m)
    if False:
        pass
    elif IPv4len == l:
        if len(ip) != IPv4len:
            return nil, nil
    elif IPv6len == l:
        if len(ip) == IPv4len:
            m = m[12:]
    else:
        return nil, nil
    return ip, m


# Contains reports whether the network includes ip.
def Contains(ip, n):
    nn, m = networkNumberAndMask(n)
    x = To4(ip)
    if x != nil:
        ip = x
    l = len(ip)
    if l != len(nn):
        return False
    for i in range(l):
        if nn[i] & m[i] != ip[i] & m[i]:
            return False
    return True


# Parse IPv4 address (d.d.d.d).
def parseIPv4(s):
    p = [0] * IPv4len
    for i in range(IPv4len):
        if len(s) == 0:
            # Missing octets.
            return nil
        if i > 0:
            if s[0] != ".":
                return nil
            s = s[1:]
        n, c, ok = dtoi(s)
        if not ok or n > 0xFF:
            return nil
        if c > 1 and s[0] == "0":
            # Reject non-zero components with leading zeroes.
            return nil
        s = s[c:]
        p[i] = byte(n)
    if len(s) != 0:
        return nil
    return IPv4(p[0], p[1], p[2], p[3])


# parseIPv6 parses s as a literal IPv6 address described in RFC 4291
# and RFC 5952.
def parseIPv6(s):
    ip = [0] * IPv6len
    ellipsis = -1  # position of ellipsis in ip

    # Might have leading ellipsis
    if len(s) >= 2 and s[0] == ":" and s[1] == ":":
        ellipsis = 0
        s = s[2:]
        # Might be only ellipsis
        if len(s) == 0:
            return ip

    # Loop, parsing hex numbers followed by colon.
    i = 0
    for ignore in range(IPv6len):
        if not (i < IPv6len):
            break
        # Hex number.
        n, c, ok = xtoi(s)
        if not ok or n > 0xFFFF:
            return nil

        # If followed by dot, might be in trailing IPv4.
        if c < len(s) and s[c] == ".":
            if ellipsis < 0 and i != IPv6len - IPv4len:
                # Not the right place.
                return nil
            if i + IPv4len > IPv6len:
                # Not enough room.
                return nil
            ip4 = parseIPv4(s)
            if ip4 == nil:
                return nil
            ip[i] = ip4[12]
            ip[i + 1] = ip4[13]
            ip[i + 2] = ip4[14]
            ip[i + 3] = ip4[15]
            s = ""
            i += IPv4len
            break

        # Save this 16-bit chunk.
        ip[i] = byte(n >> 8)
        ip[i + 1] = byte(n)
        i += 2

        # Stop at end of string.
        s = s[c:]
        if len(s) == 0:
            break

        # Otherwise must be followed by colon and more.
        if s[0] != ":" or len(s) == 1:
            return nil
        s = s[1:]

        # Look for ellipsis.
        if s[0] == ":":
            if ellipsis >= 0:  # already have one
                return nil
            ellipsis = i
            s = s[1:]
            if len(s) == 0:  # can be at end
                break

    # Must have used entire string.
    if len(s) != 0:
        return nil

    # If didn't parse enough, expand ellipsis.
    if i < IPv6len:
        if ellipsis < 0:
            return nil
        n = IPv6len - i
        for j in range(i - 1, ellipsis - 1, -1):
            ip[j + n] = ip[j]
        for j in range(ellipsis + n - 1, ellipsis - 1, -1):
            ip[j] = 0
    elif ellipsis >= 0:
        # Ellipsis must represent at least one 0 group.
        return nil
    return ip


# ParseIP parses s as an IP address, returning the result.
# The string s can be in IPv4 dotted decimal ("192.0.2.1"), IPv6
# ("2001:db8::68"), or IPv4-mapped IPv6 ("::ffff:192.0.2.1") form.
# If s is not a valid textual representation of an IP address,
# ParseIP returns nil.
def ParseIP(s):
    for i in range(len(s)):
        if False:
            pass
        elif "." == s[i]:
            return parseIPv4(s)
        elif ":" == s[i]:
            return parseIPv6(s)
    return nil


# ParseCIDR parses s as a CIDR notation IP address and prefix length,
# like "192.0.2.0/24" or "2001:db8::/32", as defined in
# RFC 4632 and RFC 4291.
#
# It returns the IP address and the network implied by the IP and
# prefix length.
# For example, ParseCIDR("192.0.2.1/24") returns the IP address
# 192.0.2.1 and the network 192.0.2.0/24.
def ParseCIDR(s):
    i = s.find("/")
    if i < 0:
        return nil, nil, {"Type": "CIDR address", "Text": s}
    addr, mask = s[:i], s[i + 1 :]
    iplen = IPv4len
    ip = parseIPv4(addr)
    if ip == nil:
        iplen = IPv6len
        ip = parseIPv6(addr)
    n, i, ok = dtoi(mask)
    if ip == nil or not ok or i != len(mask) or n < 0 or n > 8 * iplen:
        return nil, nil, {"Type": "CIDR address", "Text": s}
    m = CIDRMask(n, 8 * iplen)
    return ip, {"IP": Mask(m, ip), "Mask": m}, nil


"""
filter
"""


def rule_Match(metadata, rule):
    if rule[0] == "DOMAIN-SUFFIX":
        domain = metadata["host"]
        return domain.endswith("." + rule[1]) or rule[1] == domain
    if rule[0] == "DOMAIN-KEYWORD":
        return rule[1] in metadata["host"]
    if rule[0] == "DOMAIN":
        return rule[1] == metadata["host"]

    # IP-CIDR6 is handled the same way as IP-CIDR
    # rule[1] = {IP, Mask}
    #
    # see: https://github.com/Dreamacro/clash/blob/master/rule/ipcidr.go
    if "IP-CIDR" in rule[0]:
        ip = metadata["src_ipp"] if rule[0] == "SRC-IP-CIDR" else metadata["dst_ipp"]
        return ip != nil and Contains(ip, rule[1])

    if rule[0] == "GEOIP":
        ip = metadata["dst_ipp"]
        if ip == nil:
            return False

        if EqualFold(rule[1], "LAN"):
            return IsPrivate(ip)
        return EqualFold(metadata["IsoCode"], rule[1])

    if rule[0] == "SRT-PORT":
        return metadata["src_port"] == rule[1]
    if rule[0] == "DST-PORT":
        return metadata["dst_port"] == rule[1]

    if rule[0] == "PROCESS-NAME":
        return EqualFold(metadata["ProcessName"], rule[1])
    if rule[0] == "PROCESS-PATH":
        return EqualFold(metadata["ProcessPath"], rule[1])

    # Maybe always true, otherwise it's an illegal rule.
    return rule[0] == "MATCH"


# return: Proxy{ProxyAdapter{Name: 'Policy', SupportUDP: bool}, Alive: bool}
def rule_Adapter(pp, rule):
    policy = rule[1] if rule[0] == "MATCH" else rule[2]
    return {"Adapter": {"Name": policy, "SupportUDP": True}, "Alive": pp[policy]}


def setMetadata(ctx, metadata, k, v, *args):
    if v == ctx:
        if False:
            pass
        elif k == "ProcessPath" or k == "ProcessName":
            k = "ProcessPath"
            v = ctx.resolve_process_name
        elif k == "dst_ip":
            v = ctx.resolve_ip(metadata["host"])

    if type(v) == "function":
        v = v(args if len(args) > 0 else metadata)

    if k == v:
        v = metadata[k]
    else:
        metadata[k] = v

    if False:
        pass
    elif k == "ProcessPath":
        metadata["ProcessName"] = Base(v)
    elif k == "src_ip":
        metadata["src_ipp"] = ParseIP(v)
    elif k == "dst_ip":
        metadata["dst_ipp"] = ParseIP(v)
        metadata["IsoCode"] = ctx.geoip(v)


def shouldResolveIP(metadata, rule):
    return (
        "IP" in rule[0]
        and not (len(rule) > 3 and "no-resolve" in rule[3])
        and metadata["host"] != ""
        and metadata["dst_ip"] == ""
    )


# reimplement ctx.rule_providers.match(metadata) => boolean
# return: 'Policy', 'original_rule_string'
#
# see: https://github.com/Dreamacro/clash/blob/master/tunnel/tunnel.go
def match(ctx, metadata):
    pp = {p.name: p.alive for p in ctx.proxy_providers["default"]}
    setMetadata(ctx, metadata, "dst_ip", "dst_ip")
    setMetadata(ctx, metadata, "src_ip", "src_ip")

    resolved = False
    processFound = False

    # rule[:-2] = ['Type', 'Matcher', 'Policy']
    # rule[:-2] = ['Type', 'Matcher', 'Policy', 'Option']
    #
    # rule[:-2] = ['MATCH', 'Policy']
    #
    # rule[-1] = 'original_rule_string'
    for rule in RULES:
        if not resolved and shouldResolveIP(metadata, rule):
            setMetadata(ctx, metadata, "dst_ip", ctx)
            resolved = True

        if not processFound and "PROCESS" in rule[0]:
            processFound = True
            setMetadata(ctx, metadata, "ProcessPath", ctx)

        if rule_Match(metadata, rule):
            adapter, ok = rule_Adapter(pp, rule)
            if not ok:
                continue
            if metadata["network"] == "udp" and not adapter["SupportUDP"]:
                continue
            return adapter["Name"], rule[-1]

    return "DIRECT", nil


# see: https://github.com/Dreamacro/clash/wiki/premium-core-features
# see: https://lancellc.gitbook.io/clash/clash-config-file/script
# see: https://github.com/bazelbuild/starlark/blob/master/spec.md
def main(ctx, metadata):
    proxy, rule = match(ctx, metadata)
    if rule != nil:
        msg = [
            "[{0}]".format(metadata["network"].upper()),
            "type=" + metadata["type"],
            "host=" + metadata["host"],
            "src={0}:{1}".format(metadata["src_ip"], metadata["src_port"]),
            "dst={0}:{1}".format(metadata["dst_ip"], metadata["dst_port"]),
        ]
        ctx.log("{0} | {1}".format(" ".join(msg), rule))
    return proxy
