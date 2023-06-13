nil = None


# 模拟整数溢出
#
# a: int8(0x01) << 7 >> 7 == 0x01 << 7 >> 7 == 0x01
# b: int8(0x01 << 7) >> 7 == 0xFF
# 由于整数可以任意大，导致a与b结果不同，当左移操作需要溢出时，
# 必须套用该函数（如b所示）。
def int8(x, maxint=0x7F):
    signbit = maxint + 1

    if "string" in type(x):
        # (maxint << 1) + 1 == maxint * 2 + 1 == maxint + (maxint + 1)
        return ord(x) & maxint + signbit

    if not -signbit <= x <= maxint:
        x = (x + signbit) % (2 * signbit) - signbit
    return x


int16 = lambda x: int8(x, 0x7FFF)
int32 = lambda x: int8(x, 0x7FFFFFFF)
int64 = lambda x: int8(x, 0x7FFFFFFFFFFFFFFF)

uint8 = lambda x, maxint=0xFF: int8(x, maxint >> 1) & maxint

uint16 = lambda x: uint8(x, 0xFFFF)
uint32 = lambda x: uint8(x, 0xFFFFFFFF)
uint64 = lambda x: uint8(x, 0xFFFFFFFFFFFFFFFF)

byte = uint8
uint = uint64
rune = int32

# 一个理论上的无限循环长度（最大Unicode代码点数）
InfiniteLoop = range(0x110000)


###############################################################
# 修复starlark-go实现与官方定义有出入的部分
#
# https://github.com/bazelbuild/starlark/blob/master/spec.md
# https://github.com/google/starlark-go/blob/master/doc/spec.md
###############################################################
elem_ords = lambda s: list(s.elem_ords())
codepoint_ords = lambda s: list(s.codepoint_ords())
codepoints = lambda s: list(s.codepoints())


# 在starlark-go中，string由bytes实现，因此len在处理string时会引发歧义。
# 建议替换所有len，当需要bytes时推荐使用string.elem_ords
def slen(s):
    if "string" in type(s):
        return len(codepoints(s))
    return len(s)


###############################################################
# Package utf8 implements functions and constants to support text encoded in
# UTF-8. It includes functions to translate between runes and UTF-8 byte sequences.
# See https://en.wikipedia.org/wiki/UTF-8
#
# https://github.com/golang/go/blob/master/src/unicode/utf8/utf8.go
###############################################################
# Numbers fundamental to the encoding.
utf8_RuneError = rune('\uFFFD')  # the "error" Rune or "Unicode replacement character"
utf8_RuneSelf = 0x80  # characters below RuneSelf are represented as themselves in a single byte. fmt: skip

utf8_maskx = 0b00111111
utf8_mask2 = 0b00011111
utf8_mask3 = 0b00001111
utf8_mask4 = 0b00000111

# The default lowest and highest continuation byte.
utf8_locb = 0b10000000
utf8_hicb = 0b10111111

# These names of these constants are chosen to give nice alignment in the
# table below. The first nibble is an index into acceptRanges or F for
# special one-byte cases. The second nibble is the Rune length or the
# Status for the special one-byte case.
utf8_xx = 0xF1  # invalid: size 1
utf8_as = 0xF0  # ASCII: size 1
utf8_s1 = 0x02  # accept 0, size 2
utf8_s2 = 0x13  # accept 1, size 3
utf8_s3 = 0x03  # accept 0, size 3
utf8_s4 = 0x23  # accept 2, size 3
utf8_s5 = 0x34  # accept 3, size 4
utf8_s6 = 0x04  # accept 0, size 4
utf8_s7 = 0x44  # accept 4, size 4

# fmt: off
# first is information about the first byte in a UTF-8 sequence.
utf8_first = [
    #              1        2        3        4        5        6        7        8        9        A        B        C        D        E        F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x00-0x0F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x10-0x1F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x20-0x2F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x30-0x3F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x40-0x4F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x50-0x5F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x60-0x6F
    utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as, utf8_as,  # 0x70-0x7F
    #              1        2        3        4        5        6        7        8        9        A        B        C        D        E        F
    utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx,  # 0x80-0x8F
    utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx,  # 0x90-0x9F
    utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx,  # 0xA0-0xAF
    utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx,  # 0xB0-0xBF
    utf8_xx, utf8_xx, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1,  # 0xC0-0xCF
    utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1, utf8_s1,  # 0xD0-0xDF
    utf8_s2, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s3, utf8_s4, utf8_s3, utf8_s3,  # 0xE0-0xEF
    utf8_s5, utf8_s6, utf8_s6, utf8_s6, utf8_s7, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx, utf8_xx,  # 0xF0-0xFF
]
# fmt: on

# // acceptRange gives the range of valid values for the second byte in a UTF-8
# // sequence.
# type acceptRange struct {
#   lo uint8 // lowest value for second byte.
#   hi uint8 // highest value for second byte.
# }

# // acceptRanges has size 16 to avoid bounds checks in the code that uses it.
# var acceptRanges = [16]acceptRange{
#   0: {locb, hicb},
#   1: {0xA0, hicb},
#   2: {locb, 0x9F},
#   3: {0x90, hicb},
#   4: {locb, 0x8F},
# }
utf8_acceptRanges = [
    {"lo": utf8_locb, "hi": utf8_hicb},
    {"lo": 0xA0, "hi": utf8_hicb},
    {"lo": utf8_locb, "hi": 0x9F},
    {"lo": 0x90, "hi": utf8_hicb},
    {"lo": utf8_locb, "hi": 0x8F},
]


# DecodeRuneInString is like DecodeRune but its input is a string. If s is
# empty it returns (RuneError, 0). Otherwise, if the encoding is invalid, it
# returns (RuneError, 1). Both are impossible results for correct, non-empty
# UTF-8.
#
# An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
# out of range, or is not the shortest possible UTF-8 encoding for the
# value. No other validation is performed.
def utf8_DecodeRuneInString(s):
    s = elem_ords(s)

    n = len(s)
    if n < 1:
        return utf8_RuneError, 0
    s0 = s[0]
    x = utf8_first[s0]
    if x >= utf8_as:
        # The following code simulates an additional check for x == xx and
        # handling the ASCII and invalid cases accordingly. This mask-and-or
        # approach prevents an additional branch.
        mask = rune(x << 31) >> 31  # Create 0x0000 or 0xFFFF.
        return rune(s[0]) & ~mask | utf8_RuneError & mask, 1
    sz = int(x & 7)
    accept = utf8_acceptRanges[x >> 4]
    if n < sz:
        return utf8_RuneError, 1
    s1 = s[1]
    if s1 < accept["lo"] or accept["hi"] < s1:
        return utf8_RuneError, 1
    if sz <= 2:  # <= instead of == to help the compiler eliminate some bounds checks
        return rune(s0 & utf8_mask2) << 6 | rune(s1 & utf8_maskx), 2
    s2 = s[2]
    if s2 < utf8_locb or utf8_hicb < s2:
        return utf8_RuneError, 1
    if sz <= 3:
        return rune(s0 & utf8_mask3) << 12 | rune(s1 & utf8_maskx) << 6 | rune(s2 & utf8_maskx), 3  # fmt: skip
    s3 = s[3]
    if s3 < utf8_locb or utf8_hicb < s3:
        return utf8_RuneError, 1
    return rune(s0 & utf8_mask4) << 18 | rune(s1 & utf8_maskx) << 12 | rune(s2 & utf8_maskx) << 6 | rune(s3 & utf8_maskx), 4  # fmt: skip


###############################################################
# Package unicode provides data and functions to test some properties of
# Unicode code points.
#
# https://github.com/golang/go/blob/master/src/unicode/letter.go
# https://github.com/golang/go/blob/master/src/unicode/tables.go
###############################################################
unicode_MaxRune = rune('\U0010FFFF')  # Maximum valid Unicode code point.
unicode_ReplacementChar = rune('\uFFFD')  # Represents invalid code points.
unicode_MaxASCII = rune('\u007F')  # maximum ASCII value.

# // CaseRange represents a range of Unicode code points for simple (one
# // code point to one code point) case conversion.
# // The range runs from Lo to Hi inclusive, with a fixed stride of 1. Deltas
# // are the number to add to the code point to reach the code point for a
# // different case for that character. They may be negative. If zero, it
# // means the character is in the corresponding case. There is a special
# // case representing sequences of alternating corresponding Upper and Lower
# // pairs. It appears with a fixed Delta of
# //
# //    {UpperLower, UpperLower, UpperLower}
# //
# // The constant UpperLower has an otherwise impossible delta value.
# type CaseRange struct {
#   Lo    uint32
#   Hi    uint32
#   Delta [MaxCase]rune
# }

# // Indices into the Delta arrays inside CaseRanges for case mapping.
unicode_UpperCase = 0
unicode_LowerCase = 1
unicode_MaxCase = 3

# If the Delta field of a CaseRange is UpperLower, it means
# this CaseRange represents a sequence of the form (say)
# Upper Lower Upper Lower.
unicode_UpperLower = unicode_MaxRune + 1  # (Cannot be a valid delta.)


# to maps the rune using the specified case mapping.
# It additionally reports whether caseRange contained a mapping for r.
def unicode_to(_case, r, caseRange):
    if _case < 0 or unicode_MaxCase <= _case:
        return unicode_ReplacementChar, False  # as reasonable an error as any
    # binary search over ranges
    lo = 0
    hi = len(caseRange)
    for _ in InfiniteLoop:
        if not lo < hi:
            break
        m = lo + (hi - lo) / 2
        cr = caseRange[m]
        if rune(cr["Lo"]) <= r and r <= rune(cr["Hi"]):
            delta = cr["Delta"][_case]
            if delta > unicode_MaxRune:
                # In an Upper-Lower sequence, which always starts with
                # an UpperCase letter, the real deltas always look like:
                #   {0, 1, 0}    UpperCase (Lower is next)
                #   {-1, 0, -1}  LowerCase (Upper, Title are previous)
                # The characters at even offsets from the beginning of the
                # sequence are upper case; the ones at odd offsets are lower.
                # The correct mapping can be done by clearing or setting the low
                # bit in the sequence offset.
                # The constants UpperCase and TitleCase are even while LowerCase
                # is odd so we take the low bit from _case.
                return rune(cr["Lo"]) + ((r - rune(cr["Lo"])) & ~1 | rune(_case & 1)), True  # fmt: skip
            return r + delta, True
        if r < rune(cr["Lo"]):
            hi = m
        else:
            lo = m + 1
    return r, False


# To maps the rune to the specified case: UpperCase, LowerCase, or TitleCase.
def unicode_To(_case, r):
    r, _ = unicode_to(_case, r, unicode_CaseRanges)
    return r


# ToUpper maps the rune to upper case.
def unicode_ToUpper(r):
    if r <= unicode_MaxASCII:
        if rune('a') <= r and r <= rune('z'):
            r -= rune('a') - rune('A')
        return r
    return unicode_To(unicode_UpperCase, r)


# ToLower maps the rune to lower case.
def unicode_ToLower(r):
    if r <= unicode_MaxASCII:
        if rune('A') <= r and r <= rune('Z'):
            r += rune('a') - rune('A')
        return r
    return unicode_To(unicode_LowerCase, r)


# // caseOrbit is defined in tables.go as []foldPair. Right now all the
# // entries fit in uint16, so use uint16. If that changes, compilation
# // will fail (the constants in the composite literal will not fit in uint16)
# // and the types here can change to uint32.
# type foldPair struct {
#   From uint16
#   To   uint16
# }


# SimpleFold iterates over Unicode code points equivalent under
# the Unicode-defined simple case folding. Among the code points
# equivalent to rune (including rune itself), SimpleFold returns the
# smallest rune > r if one exists, or else the smallest rune >= 0.
# If r is not a valid Unicode code point, SimpleFold(r) returns r.
#
# For example:
#
#   SimpleFold('A') = 'a'
#   SimpleFold('a') = 'A'
#
#   SimpleFold('K') = 'k'
#   SimpleFold('k') = '\u212A' (Kelvin symbol, K)
#   SimpleFold('\u212A') = 'K'
#
#   SimpleFold('1') = '1'
#
#   SimpleFold(-2) = -2
def unicode_SimpleFold(r):
    if r < 0 or r > unicode_MaxRune:
        return r

    if int(r) < len(unicode_asciiFold):
        return rune(unicode_asciiFold[r])

    # Consult caseOrbit table for special cases.
    lo = 0
    hi = len(unicode_caseOrbit)
    for _ in InfiniteLoop:
        if not lo < hi:
            break
        m = lo + (hi - lo) / 2
        if rune(unicode_caseOrbit[m]["From"] < r):
            lo = m + 1
        else:
            hi = m
    if lo < len(unicode_caseOrbit) and rune(unicode_caseOrbit[lo]["From"]) == r:
        return rune(unicode_caseOrbit[lo]["To"])

    # No folding specified. This is a one- or two-element
    # equivalence class containing rune and ToLower(rune)
    # and ToUpper(rune) if they are different from rune.
    l = unicode_ToLower(r)
    if l != r:
        return l
    return unicode_ToUpper(r)


# fmt: off
# CaseRanges is the table describing case mappings for all letters with
# non-self mappings.
unicode_CaseRanges = [
    {"Lo": 0x00041, "Hi": 0x0005A, "Delta": [0, 32, 0]},
    {"Lo": 0x00061, "Hi": 0x0007A, "Delta": [-32, 0, -32]},
    {"Lo": 0x000B5, "Hi": 0x000B5, "Delta": [743, 0, 743]},
    {"Lo": 0x000C0, "Hi": 0x000D6, "Delta": [0, 32, 0]},
    {"Lo": 0x000D8, "Hi": 0x000DE, "Delta": [0, 32, 0]},
    {"Lo": 0x000E0, "Hi": 0x000F6, "Delta": [-32, 0, -32]},
    {"Lo": 0x000F8, "Hi": 0x000FE, "Delta": [-32, 0, -32]},
    {"Lo": 0x000FF, "Hi": 0x000FF, "Delta": [121, 0, 121]},
    {"Lo": 0x00100, "Hi": 0x0012F, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00130, "Hi": 0x00130, "Delta": [0, -199, 0]},
    {"Lo": 0x00131, "Hi": 0x00131, "Delta": [-232, 0, -232]},
    {"Lo": 0x00132, "Hi": 0x00137, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00139, "Hi": 0x00148, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0014A, "Hi": 0x00177, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00178, "Hi": 0x00178, "Delta": [0, -121, 0]},
    {"Lo": 0x00179, "Hi": 0x0017E, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0017F, "Hi": 0x0017F, "Delta": [-300, 0, -300]},
    {"Lo": 0x00180, "Hi": 0x00180, "Delta": [195, 0, 195]},
    {"Lo": 0x00181, "Hi": 0x00181, "Delta": [0, 210, 0]},
    {"Lo": 0x00182, "Hi": 0x00185, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00186, "Hi": 0x00186, "Delta": [0, 206, 0]},
    {"Lo": 0x00187, "Hi": 0x00188, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00189, "Hi": 0x0018A, "Delta": [0, 205, 0]},
    {"Lo": 0x0018B, "Hi": 0x0018C, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0018E, "Hi": 0x0018E, "Delta": [0, 79, 0]},
    {"Lo": 0x0018F, "Hi": 0x0018F, "Delta": [0, 202, 0]},
    {"Lo": 0x00190, "Hi": 0x00190, "Delta": [0, 203, 0]},
    {"Lo": 0x00191, "Hi": 0x00192, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00193, "Hi": 0x00193, "Delta": [0, 205, 0]},
    {"Lo": 0x00194, "Hi": 0x00194, "Delta": [0, 207, 0]},
    {"Lo": 0x00195, "Hi": 0x00195, "Delta": [97, 0, 97]},
    {"Lo": 0x00196, "Hi": 0x00196, "Delta": [0, 211, 0]},
    {"Lo": 0x00197, "Hi": 0x00197, "Delta": [0, 209, 0]},
    {"Lo": 0x00198, "Hi": 0x00199, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0019A, "Hi": 0x0019A, "Delta": [163, 0, 163]},
    {"Lo": 0x0019C, "Hi": 0x0019C, "Delta": [0, 211, 0]},
    {"Lo": 0x0019D, "Hi": 0x0019D, "Delta": [0, 213, 0]},
    {"Lo": 0x0019E, "Hi": 0x0019E, "Delta": [130, 0, 130]},
    {"Lo": 0x0019F, "Hi": 0x0019F, "Delta": [0, 214, 0]},
    {"Lo": 0x001A0, "Hi": 0x001A5, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001A6, "Hi": 0x001A6, "Delta": [0, 218, 0]},
    {"Lo": 0x001A7, "Hi": 0x001A8, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001A9, "Hi": 0x001A9, "Delta": [0, 218, 0]},
    {"Lo": 0x001AC, "Hi": 0x001AD, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001AE, "Hi": 0x001AE, "Delta": [0, 218, 0]},
    {"Lo": 0x001AF, "Hi": 0x001B0, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001B1, "Hi": 0x001B2, "Delta": [0, 217, 0]},
    {"Lo": 0x001B3, "Hi": 0x001B6, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001B7, "Hi": 0x001B7, "Delta": [0, 219, 0]},
    {"Lo": 0x001B8, "Hi": 0x001B9, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001BC, "Hi": 0x001BD, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001BF, "Hi": 0x001BF, "Delta": [56, 0, 56]},
    {"Lo": 0x001C4, "Hi": 0x001C4, "Delta": [0, 2, 1]},
    {"Lo": 0x001C5, "Hi": 0x001C5, "Delta": [-1, 1, 0]},
    {"Lo": 0x001C6, "Hi": 0x001C6, "Delta": [-2, 0, -1]},
    {"Lo": 0x001C7, "Hi": 0x001C7, "Delta": [0, 2, 1]},
    {"Lo": 0x001C8, "Hi": 0x001C8, "Delta": [-1, 1, 0]},
    {"Lo": 0x001C9, "Hi": 0x001C9, "Delta": [-2, 0, -1]},
    {"Lo": 0x001CA, "Hi": 0x001CA, "Delta": [0, 2, 1]},
    {"Lo": 0x001CB, "Hi": 0x001CB, "Delta": [-1, 1, 0]},
    {"Lo": 0x001CC, "Hi": 0x001CC, "Delta": [-2, 0, -1]},
    {"Lo": 0x001CD, "Hi": 0x001DC, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001DD, "Hi": 0x001DD, "Delta": [-79, 0, -79]},
    {"Lo": 0x001DE, "Hi": 0x001EF, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001F1, "Hi": 0x001F1, "Delta": [0, 2, 1]},
    {"Lo": 0x001F2, "Hi": 0x001F2, "Delta": [-1, 1, 0]},
    {"Lo": 0x001F3, "Hi": 0x001F3, "Delta": [-2, 0, -1]},
    {"Lo": 0x001F4, "Hi": 0x001F5, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x001F6, "Hi": 0x001F6, "Delta": [0, -97, 0]},
    {"Lo": 0x001F7, "Hi": 0x001F7, "Delta": [0, -56, 0]},
    {"Lo": 0x001F8, "Hi": 0x0021F, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00220, "Hi": 0x00220, "Delta": [0, -130, 0]},
    {"Lo": 0x00222, "Hi": 0x00233, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0023A, "Hi": 0x0023A, "Delta": [0, 10795, 0]},
    {"Lo": 0x0023B, "Hi": 0x0023C, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0023D, "Hi": 0x0023D, "Delta": [0, -163, 0]},
    {"Lo": 0x0023E, "Hi": 0x0023E, "Delta": [0, 10792, 0]},
    {"Lo": 0x0023F, "Hi": 0x00240, "Delta": [10815, 0, 10815]},
    {"Lo": 0x00241, "Hi": 0x00242, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00243, "Hi": 0x00243, "Delta": [0, -195, 0]},
    {"Lo": 0x00244, "Hi": 0x00244, "Delta": [0, 69, 0]},
    {"Lo": 0x00245, "Hi": 0x00245, "Delta": [0, 71, 0]},
    {"Lo": 0x00246, "Hi": 0x0024F, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00250, "Hi": 0x00250, "Delta": [10783, 0, 10783]},
    {"Lo": 0x00251, "Hi": 0x00251, "Delta": [10780, 0, 10780]},
    {"Lo": 0x00252, "Hi": 0x00252, "Delta": [10782, 0, 10782]},
    {"Lo": 0x00253, "Hi": 0x00253, "Delta": [-210, 0, -210]},
    {"Lo": 0x00254, "Hi": 0x00254, "Delta": [-206, 0, -206]},
    {"Lo": 0x00256, "Hi": 0x00257, "Delta": [-205, 0, -205]},
    {"Lo": 0x00259, "Hi": 0x00259, "Delta": [-202, 0, -202]},
    {"Lo": 0x0025B, "Hi": 0x0025B, "Delta": [-203, 0, -203]},
    {"Lo": 0x0025C, "Hi": 0x0025C, "Delta": [42319, 0, 42319]},
    {"Lo": 0x00260, "Hi": 0x00260, "Delta": [-205, 0, -205]},
    {"Lo": 0x00261, "Hi": 0x00261, "Delta": [42315, 0, 42315]},
    {"Lo": 0x00263, "Hi": 0x00263, "Delta": [-207, 0, -207]},
    {"Lo": 0x00265, "Hi": 0x00265, "Delta": [42280, 0, 42280]},
    {"Lo": 0x00266, "Hi": 0x00266, "Delta": [42308, 0, 42308]},
    {"Lo": 0x00268, "Hi": 0x00268, "Delta": [-209, 0, -209]},
    {"Lo": 0x00269, "Hi": 0x00269, "Delta": [-211, 0, -211]},
    {"Lo": 0x0026A, "Hi": 0x0026A, "Delta": [42308, 0, 42308]},
    {"Lo": 0x0026B, "Hi": 0x0026B, "Delta": [10743, 0, 10743]},
    {"Lo": 0x0026C, "Hi": 0x0026C, "Delta": [42305, 0, 42305]},
    {"Lo": 0x0026F, "Hi": 0x0026F, "Delta": [-211, 0, -211]},
    {"Lo": 0x00271, "Hi": 0x00271, "Delta": [10749, 0, 10749]},
    {"Lo": 0x00272, "Hi": 0x00272, "Delta": [-213, 0, -213]},
    {"Lo": 0x00275, "Hi": 0x00275, "Delta": [-214, 0, -214]},
    {"Lo": 0x0027D, "Hi": 0x0027D, "Delta": [10727, 0, 10727]},
    {"Lo": 0x00280, "Hi": 0x00280, "Delta": [-218, 0, -218]},
    {"Lo": 0x00282, "Hi": 0x00282, "Delta": [42307, 0, 42307]},
    {"Lo": 0x00283, "Hi": 0x00283, "Delta": [-218, 0, -218]},
    {"Lo": 0x00287, "Hi": 0x00287, "Delta": [42282, 0, 42282]},
    {"Lo": 0x00288, "Hi": 0x00288, "Delta": [-218, 0, -218]},
    {"Lo": 0x00289, "Hi": 0x00289, "Delta": [-69, 0, -69]},
    {"Lo": 0x0028A, "Hi": 0x0028B, "Delta": [-217, 0, -217]},
    {"Lo": 0x0028C, "Hi": 0x0028C, "Delta": [-71, 0, -71]},
    {"Lo": 0x00292, "Hi": 0x00292, "Delta": [-219, 0, -219]},
    {"Lo": 0x0029D, "Hi": 0x0029D, "Delta": [42261, 0, 42261]},
    {"Lo": 0x0029E, "Hi": 0x0029E, "Delta": [42258, 0, 42258]},
    {"Lo": 0x00345, "Hi": 0x00345, "Delta": [84, 0, 84]},
    {"Lo": 0x00370, "Hi": 0x00373, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00376, "Hi": 0x00377, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0037B, "Hi": 0x0037D, "Delta": [130, 0, 130]},
    {"Lo": 0x0037F, "Hi": 0x0037F, "Delta": [0, 116, 0]},
    {"Lo": 0x00386, "Hi": 0x00386, "Delta": [0, 38, 0]},
    {"Lo": 0x00388, "Hi": 0x0038A, "Delta": [0, 37, 0]},
    {"Lo": 0x0038C, "Hi": 0x0038C, "Delta": [0, 64, 0]},
    {"Lo": 0x0038E, "Hi": 0x0038F, "Delta": [0, 63, 0]},
    {"Lo": 0x00391, "Hi": 0x003A1, "Delta": [0, 32, 0]},
    {"Lo": 0x003A3, "Hi": 0x003AB, "Delta": [0, 32, 0]},
    {"Lo": 0x003AC, "Hi": 0x003AC, "Delta": [-38, 0, -38]},
    {"Lo": 0x003AD, "Hi": 0x003AF, "Delta": [-37, 0, -37]},
    {"Lo": 0x003B1, "Hi": 0x003C1, "Delta": [-32, 0, -32]},
    {"Lo": 0x003C2, "Hi": 0x003C2, "Delta": [-31, 0, -31]},
    {"Lo": 0x003C3, "Hi": 0x003CB, "Delta": [-32, 0, -32]},
    {"Lo": 0x003CC, "Hi": 0x003CC, "Delta": [-64, 0, -64]},
    {"Lo": 0x003CD, "Hi": 0x003CE, "Delta": [-63, 0, -63]},
    {"Lo": 0x003CF, "Hi": 0x003CF, "Delta": [0, 8, 0]},
    {"Lo": 0x003D0, "Hi": 0x003D0, "Delta": [-62, 0, -62]},
    {"Lo": 0x003D1, "Hi": 0x003D1, "Delta": [-57, 0, -57]},
    {"Lo": 0x003D5, "Hi": 0x003D5, "Delta": [-47, 0, -47]},
    {"Lo": 0x003D6, "Hi": 0x003D6, "Delta": [-54, 0, -54]},
    {"Lo": 0x003D7, "Hi": 0x003D7, "Delta": [-8, 0, -8]},
    {"Lo": 0x003D8, "Hi": 0x003EF, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x003F0, "Hi": 0x003F0, "Delta": [-86, 0, -86]},
    {"Lo": 0x003F1, "Hi": 0x003F1, "Delta": [-80, 0, -80]},
    {"Lo": 0x003F2, "Hi": 0x003F2, "Delta": [7, 0, 7]},
    {"Lo": 0x003F3, "Hi": 0x003F3, "Delta": [-116, 0, -116]},
    {"Lo": 0x003F4, "Hi": 0x003F4, "Delta": [0, -60, 0]},
    {"Lo": 0x003F5, "Hi": 0x003F5, "Delta": [-96, 0, -96]},
    {"Lo": 0x003F7, "Hi": 0x003F8, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x003F9, "Hi": 0x003F9, "Delta": [0, -7, 0]},
    {"Lo": 0x003FA, "Hi": 0x003FB, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x003FD, "Hi": 0x003FF, "Delta": [0, -130, 0]},
    {"Lo": 0x00400, "Hi": 0x0040F, "Delta": [0, 80, 0]},
    {"Lo": 0x00410, "Hi": 0x0042F, "Delta": [0, 32, 0]},
    {"Lo": 0x00430, "Hi": 0x0044F, "Delta": [-32, 0, -32]},
    {"Lo": 0x00450, "Hi": 0x0045F, "Delta": [-80, 0, -80]},
    {"Lo": 0x00460, "Hi": 0x00481, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0048A, "Hi": 0x004BF, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x004C0, "Hi": 0x004C0, "Delta": [0, 15, 0]},
    {"Lo": 0x004C1, "Hi": 0x004CE, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x004CF, "Hi": 0x004CF, "Delta": [-15, 0, -15]},
    {"Lo": 0x004D0, "Hi": 0x0052F, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x00531, "Hi": 0x00556, "Delta": [0, 48, 0]},
    {"Lo": 0x00561, "Hi": 0x00586, "Delta": [-48, 0, -48]},
    {"Lo": 0x010A0, "Hi": 0x010C5, "Delta": [0, 7264, 0]},
    {"Lo": 0x010C7, "Hi": 0x010C7, "Delta": [0, 7264, 0]},
    {"Lo": 0x010CD, "Hi": 0x010CD, "Delta": [0, 7264, 0]},
    {"Lo": 0x010D0, "Hi": 0x010FA, "Delta": [3008, 0, 0]},
    {"Lo": 0x010FD, "Hi": 0x010FF, "Delta": [3008, 0, 0]},
    {"Lo": 0x013A0, "Hi": 0x013EF, "Delta": [0, 38864, 0]},
    {"Lo": 0x013F0, "Hi": 0x013F5, "Delta": [0, 8, 0]},
    {"Lo": 0x013F8, "Hi": 0x013FD, "Delta": [-8, 0, -8]},
    {"Lo": 0x01C80, "Hi": 0x01C80, "Delta": [-6254, 0, -6254]},
    {"Lo": 0x01C81, "Hi": 0x01C81, "Delta": [-6253, 0, -6253]},
    {"Lo": 0x01C82, "Hi": 0x01C82, "Delta": [-6244, 0, -6244]},
    {"Lo": 0x01C83, "Hi": 0x01C84, "Delta": [-6242, 0, -6242]},
    {"Lo": 0x01C85, "Hi": 0x01C85, "Delta": [-6243, 0, -6243]},
    {"Lo": 0x01C86, "Hi": 0x01C86, "Delta": [-6236, 0, -6236]},
    {"Lo": 0x01C87, "Hi": 0x01C87, "Delta": [-6181, 0, -6181]},
    {"Lo": 0x01C88, "Hi": 0x01C88, "Delta": [35266, 0, 35266]},
    {"Lo": 0x01C90, "Hi": 0x01CBA, "Delta": [0, -3008, 0]},
    {"Lo": 0x01CBD, "Hi": 0x01CBF, "Delta": [0, -3008, 0]},
    {"Lo": 0x01D79, "Hi": 0x01D79, "Delta": [35332, 0, 35332]},
    {"Lo": 0x01D7D, "Hi": 0x01D7D, "Delta": [3814, 0, 3814]},
    {"Lo": 0x01D8E, "Hi": 0x01D8E, "Delta": [35384, 0, 35384]},
    {"Lo": 0x01E00, "Hi": 0x01E95, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x01E9B, "Hi": 0x01E9B, "Delta": [-59, 0, -59]},
    {"Lo": 0x01E9E, "Hi": 0x01E9E, "Delta": [0, -7615, 0]},
    {"Lo": 0x01EA0, "Hi": 0x01EFF, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x01F00, "Hi": 0x01F07, "Delta": [8, 0, 8]},
    {"Lo": 0x01F08, "Hi": 0x01F0F, "Delta": [0, -8, 0]},
    {"Lo": 0x01F10, "Hi": 0x01F15, "Delta": [8, 0, 8]},
    {"Lo": 0x01F18, "Hi": 0x01F1D, "Delta": [0, -8, 0]},
    {"Lo": 0x01F20, "Hi": 0x01F27, "Delta": [8, 0, 8]},
    {"Lo": 0x01F28, "Hi": 0x01F2F, "Delta": [0, -8, 0]},
    {"Lo": 0x01F30, "Hi": 0x01F37, "Delta": [8, 0, 8]},
    {"Lo": 0x01F38, "Hi": 0x01F3F, "Delta": [0, -8, 0]},
    {"Lo": 0x01F40, "Hi": 0x01F45, "Delta": [8, 0, 8]},
    {"Lo": 0x01F48, "Hi": 0x01F4D, "Delta": [0, -8, 0]},
    {"Lo": 0x01F51, "Hi": 0x01F51, "Delta": [8, 0, 8]},
    {"Lo": 0x01F53, "Hi": 0x01F53, "Delta": [8, 0, 8]},
    {"Lo": 0x01F55, "Hi": 0x01F55, "Delta": [8, 0, 8]},
    {"Lo": 0x01F57, "Hi": 0x01F57, "Delta": [8, 0, 8]},
    {"Lo": 0x01F59, "Hi": 0x01F59, "Delta": [0, -8, 0]},
    {"Lo": 0x01F5B, "Hi": 0x01F5B, "Delta": [0, -8, 0]},
    {"Lo": 0x01F5D, "Hi": 0x01F5D, "Delta": [0, -8, 0]},
    {"Lo": 0x01F5F, "Hi": 0x01F5F, "Delta": [0, -8, 0]},
    {"Lo": 0x01F60, "Hi": 0x01F67, "Delta": [8, 0, 8]},
    {"Lo": 0x01F68, "Hi": 0x01F6F, "Delta": [0, -8, 0]},
    {"Lo": 0x01F70, "Hi": 0x01F71, "Delta": [74, 0, 74]},
    {"Lo": 0x01F72, "Hi": 0x01F75, "Delta": [86, 0, 86]},
    {"Lo": 0x01F76, "Hi": 0x01F77, "Delta": [100, 0, 100]},
    {"Lo": 0x01F78, "Hi": 0x01F79, "Delta": [128, 0, 128]},
    {"Lo": 0x01F7A, "Hi": 0x01F7B, "Delta": [112, 0, 112]},
    {"Lo": 0x01F7C, "Hi": 0x01F7D, "Delta": [126, 0, 126]},
    {"Lo": 0x01F80, "Hi": 0x01F87, "Delta": [8, 0, 8]},
    {"Lo": 0x01F88, "Hi": 0x01F8F, "Delta": [0, -8, 0]},
    {"Lo": 0x01F90, "Hi": 0x01F97, "Delta": [8, 0, 8]},
    {"Lo": 0x01F98, "Hi": 0x01F9F, "Delta": [0, -8, 0]},
    {"Lo": 0x01FA0, "Hi": 0x01FA7, "Delta": [8, 0, 8]},
    {"Lo": 0x01FA8, "Hi": 0x01FAF, "Delta": [0, -8, 0]},
    {"Lo": 0x01FB0, "Hi": 0x01FB1, "Delta": [8, 0, 8]},
    {"Lo": 0x01FB3, "Hi": 0x01FB3, "Delta": [9, 0, 9]},
    {"Lo": 0x01FB8, "Hi": 0x01FB9, "Delta": [0, -8, 0]},
    {"Lo": 0x01FBA, "Hi": 0x01FBB, "Delta": [0, -74, 0]},
    {"Lo": 0x01FBC, "Hi": 0x01FBC, "Delta": [0, -9, 0]},
    {"Lo": 0x01FBE, "Hi": 0x01FBE, "Delta": [-7205, 0, -7205]},
    {"Lo": 0x01FC3, "Hi": 0x01FC3, "Delta": [9, 0, 9]},
    {"Lo": 0x01FC8, "Hi": 0x01FCB, "Delta": [0, -86, 0]},
    {"Lo": 0x01FCC, "Hi": 0x01FCC, "Delta": [0, -9, 0]},
    {"Lo": 0x01FD0, "Hi": 0x01FD1, "Delta": [8, 0, 8]},
    {"Lo": 0x01FD8, "Hi": 0x01FD9, "Delta": [0, -8, 0]},
    {"Lo": 0x01FDA, "Hi": 0x01FDB, "Delta": [0, -100, 0]},
    {"Lo": 0x01FE0, "Hi": 0x01FE1, "Delta": [8, 0, 8]},
    {"Lo": 0x01FE5, "Hi": 0x01FE5, "Delta": [7, 0, 7]},
    {"Lo": 0x01FE8, "Hi": 0x01FE9, "Delta": [0, -8, 0]},
    {"Lo": 0x01FEA, "Hi": 0x01FEB, "Delta": [0, -112, 0]},
    {"Lo": 0x01FEC, "Hi": 0x01FEC, "Delta": [0, -7, 0]},
    {"Lo": 0x01FF3, "Hi": 0x01FF3, "Delta": [9, 0, 9]},
    {"Lo": 0x01FF8, "Hi": 0x01FF9, "Delta": [0, -128, 0]},
    {"Lo": 0x01FFA, "Hi": 0x01FFB, "Delta": [0, -126, 0]},
    {"Lo": 0x01FFC, "Hi": 0x01FFC, "Delta": [0, -9, 0]},
    {"Lo": 0x02126, "Hi": 0x02126, "Delta": [0, -7517, 0]},
    {"Lo": 0x0212A, "Hi": 0x0212A, "Delta": [0, -8383, 0]},
    {"Lo": 0x0212B, "Hi": 0x0212B, "Delta": [0, -8262, 0]},
    {"Lo": 0x02132, "Hi": 0x02132, "Delta": [0, 28, 0]},
    {"Lo": 0x0214E, "Hi": 0x0214E, "Delta": [-28, 0, -28]},
    {"Lo": 0x02160, "Hi": 0x0216F, "Delta": [0, 16, 0]},
    {"Lo": 0x02170, "Hi": 0x0217F, "Delta": [-16, 0, -16]},
    {"Lo": 0x02183, "Hi": 0x02184, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x024B6, "Hi": 0x024CF, "Delta": [0, 26, 0]},
    {"Lo": 0x024D0, "Hi": 0x024E9, "Delta": [-26, 0, -26]},
    {"Lo": 0x02C00, "Hi": 0x02C2F, "Delta": [0, 48, 0]},
    {"Lo": 0x02C30, "Hi": 0x02C5F, "Delta": [-48, 0, -48]},
    {"Lo": 0x02C60, "Hi": 0x02C61, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02C62, "Hi": 0x02C62, "Delta": [0, -10743, 0]},
    {"Lo": 0x02C63, "Hi": 0x02C63, "Delta": [0, -3814, 0]},
    {"Lo": 0x02C64, "Hi": 0x02C64, "Delta": [0, -10727, 0]},
    {"Lo": 0x02C65, "Hi": 0x02C65, "Delta": [-10795, 0, -10795]},
    {"Lo": 0x02C66, "Hi": 0x02C66, "Delta": [-10792, 0, -10792]},
    {"Lo": 0x02C67, "Hi": 0x02C6C, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02C6D, "Hi": 0x02C6D, "Delta": [0, -10780, 0]},
    {"Lo": 0x02C6E, "Hi": 0x02C6E, "Delta": [0, -10749, 0]},
    {"Lo": 0x02C6F, "Hi": 0x02C6F, "Delta": [0, -10783, 0]},
    {"Lo": 0x02C70, "Hi": 0x02C70, "Delta": [0, -10782, 0]},
    {"Lo": 0x02C72, "Hi": 0x02C73, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02C75, "Hi": 0x02C76, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02C7E, "Hi": 0x02C7F, "Delta": [0, -10815, 0]},
    {"Lo": 0x02C80, "Hi": 0x02CE3, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02CEB, "Hi": 0x02CEE, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02CF2, "Hi": 0x02CF3, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x02D00, "Hi": 0x02D25, "Delta": [-7264, 0, -7264]},
    {"Lo": 0x02D27, "Hi": 0x02D27, "Delta": [-7264, 0, -7264]},
    {"Lo": 0x02D2D, "Hi": 0x02D2D, "Delta": [-7264, 0, -7264]},
    {"Lo": 0x0A640, "Hi": 0x0A66D, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A680, "Hi": 0x0A69B, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A722, "Hi": 0x0A72F, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A732, "Hi": 0x0A76F, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A779, "Hi": 0x0A77C, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A77D, "Hi": 0x0A77D, "Delta": [0, -35332, 0]},
    {"Lo": 0x0A77E, "Hi": 0x0A787, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A78B, "Hi": 0x0A78C, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A78D, "Hi": 0x0A78D, "Delta": [0, -42280, 0]},
    {"Lo": 0x0A790, "Hi": 0x0A793, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A794, "Hi": 0x0A794, "Delta": [48, 0, 48]},
    {"Lo": 0x0A796, "Hi": 0x0A7A9, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A7AA, "Hi": 0x0A7AA, "Delta": [0, -42308, 0]},
    {"Lo": 0x0A7AB, "Hi": 0x0A7AB, "Delta": [0, -42319, 0]},
    {"Lo": 0x0A7AC, "Hi": 0x0A7AC, "Delta": [0, -42315, 0]},
    {"Lo": 0x0A7AD, "Hi": 0x0A7AD, "Delta": [0, -42305, 0]},
    {"Lo": 0x0A7AE, "Hi": 0x0A7AE, "Delta": [0, -42308, 0]},
    {"Lo": 0x0A7B0, "Hi": 0x0A7B0, "Delta": [0, -42258, 0]},
    {"Lo": 0x0A7B1, "Hi": 0x0A7B1, "Delta": [0, -42282, 0]},
    {"Lo": 0x0A7B2, "Hi": 0x0A7B2, "Delta": [0, -42261, 0]},
    {"Lo": 0x0A7B3, "Hi": 0x0A7B3, "Delta": [0, 928, 0]},
    {"Lo": 0x0A7B4, "Hi": 0x0A7C3, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A7C4, "Hi": 0x0A7C4, "Delta": [0, -48, 0]},
    {"Lo": 0x0A7C5, "Hi": 0x0A7C5, "Delta": [0, -42307, 0]},
    {"Lo": 0x0A7C6, "Hi": 0x0A7C6, "Delta": [0, -35384, 0]},
    {"Lo": 0x0A7C7, "Hi": 0x0A7CA, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A7D0, "Hi": 0x0A7D1, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A7D6, "Hi": 0x0A7D9, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0A7F5, "Hi": 0x0A7F6, "Delta": [unicode_UpperLower, unicode_UpperLower, unicode_UpperLower]},
    {"Lo": 0x0AB53, "Hi": 0x0AB53, "Delta": [-928, 0, -928]},
    {"Lo": 0x0AB70, "Hi": 0x0ABBF, "Delta": [-38864, 0, -38864]},
    {"Lo": 0x0FF21, "Hi": 0x0FF3A, "Delta": [0, 32, 0]},
    {"Lo": 0x0FF41, "Hi": 0x0FF5A, "Delta": [-32, 0, -32]},
    {"Lo": 0x10400, "Hi": 0x10427, "Delta": [0, 40, 0]},
    {"Lo": 0x10428, "Hi": 0x1044F, "Delta": [-40, 0, -40]},
    {"Lo": 0x104B0, "Hi": 0x104D3, "Delta": [0, 40, 0]},
    {"Lo": 0x104D8, "Hi": 0x104FB, "Delta": [-40, 0, -40]},
    {"Lo": 0x10570, "Hi": 0x1057A, "Delta": [0, 39, 0]},
    {"Lo": 0x1057C, "Hi": 0x1058A, "Delta": [0, 39, 0]},
    {"Lo": 0x1058C, "Hi": 0x10592, "Delta": [0, 39, 0]},
    {"Lo": 0x10594, "Hi": 0x10595, "Delta": [0, 39, 0]},
    {"Lo": 0x10597, "Hi": 0x105A1, "Delta": [-39, 0, -39]},
    {"Lo": 0x105A3, "Hi": 0x105B1, "Delta": [-39, 0, -39]},
    {"Lo": 0x105B3, "Hi": 0x105B9, "Delta": [-39, 0, -39]},
    {"Lo": 0x105BB, "Hi": 0x105BC, "Delta": [-39, 0, -39]},
    {"Lo": 0x10C80, "Hi": 0x10CB2, "Delta": [0, 64, 0]},
    {"Lo": 0x10CC0, "Hi": 0x10CF2, "Delta": [-64, 0, -64]},
    {"Lo": 0x118A0, "Hi": 0x118BF, "Delta": [0, 32, 0]},
    {"Lo": 0x118C0, "Hi": 0x118DF, "Delta": [-32, 0, -32]},
    {"Lo": 0x16E40, "Hi": 0x16E5F, "Delta": [0, 32, 0]},
    {"Lo": 0x16E60, "Hi": 0x16E7F, "Delta": [-32, 0, -32]},
    {"Lo": 0x1E900, "Hi": 0x1E921, "Delta": [0, 34, 0]},
    {"Lo": 0x1E922, "Hi": 0x1E943, "Delta": [-34, 0, -34]},
]

unicode_asciiFold = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,

    0x0040,
            0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007A,
                                                                                            0x005B, 0x005C, 0x005D, 0x005E, 0x005F,

    0x0060,
            0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x212A, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x017F, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A,
                                                                                            0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
]
# fmt: on

unicode_caseOrbit = [
    {"From": 0x004B, "To": 0x006B},
    {"From": 0x0053, "To": 0x0073},
    {"From": 0x006B, "To": 0x212A},
    {"From": 0x0073, "To": 0x017F},
    {"From": 0x00B5, "To": 0x039C},
    {"From": 0x00C5, "To": 0x00E5},
    {"From": 0x00DF, "To": 0x1E9E},
    {"From": 0x00E5, "To": 0x212B},
    {"From": 0x0130, "To": 0x0130},
    {"From": 0x0131, "To": 0x0131},
    {"From": 0x017F, "To": 0x0053},
    {"From": 0x01C4, "To": 0x01C5},
    {"From": 0x01C5, "To": 0x01C6},
    {"From": 0x01C6, "To": 0x01C4},
    {"From": 0x01C7, "To": 0x01C8},
    {"From": 0x01C8, "To": 0x01C9},
    {"From": 0x01C9, "To": 0x01C7},
    {"From": 0x01CA, "To": 0x01CB},
    {"From": 0x01CB, "To": 0x01CC},
    {"From": 0x01CC, "To": 0x01CA},
    {"From": 0x01F1, "To": 0x01F2},
    {"From": 0x01F2, "To": 0x01F3},
    {"From": 0x01F3, "To": 0x01F1},
    {"From": 0x0345, "To": 0x0399},
    {"From": 0x0392, "To": 0x03B2},
    {"From": 0x0395, "To": 0x03B5},
    {"From": 0x0398, "To": 0x03B8},
    {"From": 0x0399, "To": 0x03B9},
    {"From": 0x039A, "To": 0x03BA},
    {"From": 0x039C, "To": 0x03BC},
    {"From": 0x03A0, "To": 0x03C0},
    {"From": 0x03A1, "To": 0x03C1},
    {"From": 0x03A3, "To": 0x03C2},
    {"From": 0x03A6, "To": 0x03C6},
    {"From": 0x03A9, "To": 0x03C9},
    {"From": 0x03B2, "To": 0x03D0},
    {"From": 0x03B5, "To": 0x03F5},
    {"From": 0x03B8, "To": 0x03D1},
    {"From": 0x03B9, "To": 0x1FBE},
    {"From": 0x03BA, "To": 0x03F0},
    {"From": 0x03BC, "To": 0x00B5},
    {"From": 0x03C0, "To": 0x03D6},
    {"From": 0x03C1, "To": 0x03F1},
    {"From": 0x03C2, "To": 0x03C3},
    {"From": 0x03C3, "To": 0x03A3},
    {"From": 0x03C6, "To": 0x03D5},
    {"From": 0x03C9, "To": 0x2126},
    {"From": 0x03D0, "To": 0x0392},
    {"From": 0x03D1, "To": 0x03F4},
    {"From": 0x03D5, "To": 0x03A6},
    {"From": 0x03D6, "To": 0x03A0},
    {"From": 0x03F0, "To": 0x039A},
    {"From": 0x03F1, "To": 0x03A1},
    {"From": 0x03F4, "To": 0x0398},
    {"From": 0x03F5, "To": 0x0395},
    {"From": 0x0412, "To": 0x0432},
    {"From": 0x0414, "To": 0x0434},
    {"From": 0x041E, "To": 0x043E},
    {"From": 0x0421, "To": 0x0441},
    {"From": 0x0422, "To": 0x0442},
    {"From": 0x042A, "To": 0x044A},
    {"From": 0x0432, "To": 0x1C80},
    {"From": 0x0434, "To": 0x1C81},
    {"From": 0x043E, "To": 0x1C82},
    {"From": 0x0441, "To": 0x1C83},
    {"From": 0x0442, "To": 0x1C84},
    {"From": 0x044A, "To": 0x1C86},
    {"From": 0x0462, "To": 0x0463},
    {"From": 0x0463, "To": 0x1C87},
    {"From": 0x1C80, "To": 0x0412},
    {"From": 0x1C81, "To": 0x0414},
    {"From": 0x1C82, "To": 0x041E},
    {"From": 0x1C83, "To": 0x0421},
    {"From": 0x1C84, "To": 0x1C85},
    {"From": 0x1C85, "To": 0x0422},
    {"From": 0x1C86, "To": 0x042A},
    {"From": 0x1C87, "To": 0x0462},
    {"From": 0x1C88, "To": 0xA64A},
    {"From": 0x1E60, "To": 0x1E61},
    {"From": 0x1E61, "To": 0x1E9B},
    {"From": 0x1E9B, "To": 0x1E60},
    {"From": 0x1E9E, "To": 0x00DF},
    {"From": 0x1FBE, "To": 0x0345},
    {"From": 0x2126, "To": 0x03A9},
    {"From": 0x212A, "To": 0x004B},
    {"From": 0x212B, "To": 0x00C5},
    {"From": 0xA64A, "To": 0xA64B},
    {"From": 0xA64B, "To": 0x1C88},
]


###############################################################
# Package strings implements simple functions to manipulate UTF-8 encoded strings.
#
# For information about UTF-8 strings in Go, see https://blog.golang.org/strings.
#
# https://github.com/golang/go/blob/master/src/strings/strings.go
###############################################################
# EqualFold reports whether s and t, interpreted as UTF-8 strings,
# are equal under simple Unicode case-folding, which is a more general
# form of case-insensitivity.
def strings_EqualFold(s, t):
    s = elem_ords(s)
    t = elem_ords(t)

    # ASCII fast path
    i = 0
    for _ in s + t:
        if not (i < len(s) and i < len(t)):
            break
        sr = s[i]
        tr = t[i]
        if sr | tr >= utf8_RuneSelf:
            return strings_EqualFold_hasUnicode(s[i:], t[i:])
        i += 1

        # Easy case.
        if tr == sr:
            continue

        # Make sr < tr to simplify what follows.
        if tr < sr:
            tr, sr = sr, tr
        # ASCII only, sr/tr must be upper/lower case
        if rune('A') <= sr and sr <= rune('Z') and tr == sr + rune('a') - rune('A'):
            continue
        return False
    # Check if we've exhausted both strings.
    return len(s) == len(t)


def strings_EqualFold_hasUnicode(s, t):
    for _, sr in enumerate(s):
        # If t is exhausted the strings are not equal.
        if len(t) == 0:
            return False

        # Extract first rune from second string.
        if t[0] < utf8_RuneSelf:
            tr, t = rune(t[0]), t[1:]
        else:
            r, size = utf8_DecodeRuneInString(t)
            tr, t = r, t[size:]

        # If they match, keep going; if not, return false.

        # Easy case.
        if tr == sr:
            continue

        # Make sr < tr to simplify what follows.
        if tr < sr:
            tr, sr = sr, tr
        # Fast check for ASCII.
        if tr < utf8_RuneSelf:
            # ASCII only, sr/tr must be upper/lower case
            if rune('A') <= sr and sr <= rune('Z') and tr == sr + rune('a') - rune('A'):
                continue
            return False

        # General case. SimpleFold(x) returns the next equivalent rune > x
        # or wraps around to smaller values.
        r = unicode_SimpleFold(sr)
        for _ in InfiniteLoop:
            if not (r != sr and r < tr):
                break
            r = unicode_SimpleFold(r)
        if r == tr:
            continue
        return False

    # First string is empty, so check if the second one is also empty.
    return len(t) == 0


###############################################################
# See: https://github.com/golang/go/blob/master/src/os/path_windows.go
###############################################################
# IsPathSeparator reports whether c is a directory separator character.
def IsPathSeparator(c):
    # NOTE: Windows accepts / as path separator.
    return c == "\\" or c == "/"


###############################################################
# See: https://github.com/golang/go/blob/master/src/path/filepath/path_windows.go
###############################################################
isSlash = IsPathSeparator


def toUpper(c):
    if "a" <= c and c <= "z":
        return chr(ord(c) - ord("a") + ord("A"))
    return c


# volumeNameLen returns length of the leading volume name on Windows.
# It returns 0 elsewhere.
#
# See: https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
def volumeNameLen(path):
    if len(path) < 2:
        return 0
    # with drive letter
    c = path[0]
    if path[1] == ":" and ("a" <= c and c <= "z" or "A" <= c and c <= "Z"):
        return 2
    # UNC and DOS device paths start with two slashes.
    if not isSlash(path[0]) or not isSlash(path[1]):
        return 0
    rest = path[2:]
    p1, rest, _ = cutPath(rest)
    p2, rest, ok = cutPath(rest)
    if not ok:
        return len(path)
    if p1 != "." and p1 != "?":
        # This is a UNC path: \\${HOST}\${SHARE}\
        return len(path) - len(rest) - 1
    # This is a DOS device path.
    if (
        len(p2) == 3
        and toUpper(p2[0]) == "U"
        and toUpper(p2[1]) == "N"
        and toUpper(p2[2]) == "C"
    ):
        # This is a DOS device path that links to a UNC: \\.\UNC\${HOST}\${SHARE}\
        _, rest, _ = cutPath(rest)  # host
        _, rest, ok = cutPath(rest)  # share
        if not ok:
            return len(path)
    return len(path) - len(rest) - 1


# cutPath slices path around the first path separator.
def cutPath(path):
    for i in range(len(path)):
        if isSlash(path[i]):
            return path[:i], path[i + 1 :], True
    return path, "", False


###############################################################
# Package filepath implements utility routines for manipulating filename paths
# in a way compatible with the target operating system-defined file paths.
#
# The filepath package uses either forward slashes or backslashes,
# depending on the operating system. To process paths such as URLs
# that always use forward slashes regardless of the operating
# system, see the [path] package.
#
# See: https://github.com/golang/go/blob/master/src/path/filepath/path.go
###############################################################
Separator = "/"


# FromSlash returns the result of replacing each slash ('/') character
# in path with a separator character. Multiple slashes are replaced
# by multiple separators.
def FromSlash(path):
    if "\\" not in path:
        return path
    return path.replace(Separator, "\\")


# Base returns the last element of path.
# Trailing path separators are removed before extracting the last element.
# If the path is empty, Base returns ".".
# If the path consists entirely of separators, Base returns a single separator.
def Base(path):
    if path == "":
        return "."
    # Strip trailing slashes.
    for _ in range(len(path)):
        if not (len(path) > 0 and IsPathSeparator(path[len(path) - 1])):
            break
        path = path[0 : len(path) - 1]
    # Throw away volume name
    path = path[len(VolumeName(path)) :]
    # Find the last element
    i = len(path) - 1
    for _ in range(len(path)):
        if not (i >= 0 and not IsPathSeparator(path[i])):
            break
        i -= 1
    if i >= 0:
        path = path[i + 1 :]
    # If empty now, it had only slashes.
    if path == "":
        return Separator
    return path


# VolumeName returns leading volume name.
# Given "C:\foo\bar" it returns "C:" on Windows.
# Given "\\host\share\foo" it returns "\\host\share".
# On other platforms it returns "".
def VolumeName(path):
    return FromSlash(path[: volumeNameLen(path)])


###############################################################
# Simple file i/o and string manipulation, to avoid
# depending on strconv and bufio and strings.
#
# See: https://github.com/golang/go/blob/master/src/net/parse.go
###############################################################
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


###############################################################
# IP address manipulations
#
# IPv4 addresses are 4 bytes; IPv6 addresses are 16 bytes.
# An IPv4 address can be converted to an IPv6 address by
# adding a canonical prefix (10 zeros, 2 0xFFs).
# This library accepts either size of byte slice but always
# returns 16-byte addresses.
#
# See: https://github.com/golang/go/blob/master/src/net/ip.go
#
# // An IP is a single IP address, a slice of bytes.
# // Functions in this package accept either 4-byte (IPv4)
# // or 16-byte (IPv6) slices as input.
# //
# // Note that in this documentation, referring to an
# // IP address as an IPv4 address or an IPv6 address
# // is a semantic property of the address, not just the
# // length of the byte slice: a 16-byte slice can still
# // be an IPv4 address.
# type IP []byte
#
# // An IPMask is a bitmask that can be used to manipulate
# // IP addresses for IP addressing and routing.
# //
# // See type IPNet and func ParseCIDR for details.
# type IPMask []byte
#
# // An IPNet represents an IP network.
# type IPNet struct {
#   IP   IP     // network number
#   Mask IPMask // network mask
# }
#
# Starlark is intended to be simple. There are no user-defined types,
# no inheritance, no reflection, no exceptions, no explicit memory management.
# Execution is finite. The language does not allow recursion or unbounded loops.
###############################################################
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
    l = int(bits / 8)
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


###############################################################
# 规则匹配区
#
# rule = [
#   "original_rule_string",
#   "Type",
#   IPNet if "IP-CIDR" in rule[1] else "Matcher",
#   "Policy",
#   "Option"
# ]
#
# Option 中新增 disable-udp 用 `;` 分割，与 Proxy Groups 中的含义一致，手动添加将忽略配置文件中的设置。
# 由于配置文件是静态的，外加脚本缺少相关接口，因此无法考虑 UDP 传递问题。
# 无论是 Proxies 的 udp 还是 Proxy Groups 的 disable-udp 它们的默认值都是 false。
# rule[4] = "no-resolve;disable-udp"
###############################################################
RULES = _RULES = []


def ruleMatch(metadata, rule):
    if rule[1] == "DOMAIN-SUFFIX":
        return metadata["host"].endswith("." + rule[2]) or rule[2] == metadata["host"]
    if rule[1] == "DOMAIN-KEYWORD":
        return rule[2] in metadata["host"]
    if rule[1] == "DOMAIN":
        return rule[2] == metadata["host"]

    if "IP-CIDR" in rule[1]:
        ip = metadata["src_ipp"] if rule[1] == "SRC-IP-CIDR" else metadata["dst_ipp"]
        return ip != nil and Contains(ip, rule[2])

    if rule[1] == "GEOIP":
        ip = metadata["dst_ipp"]
        if ip == nil:
            return False

        if EqualFold(rule[2], "LAN"):
            return IsPrivate(ip)
        return EqualFold(metadata["IsoCode"], rule[2])

    if rule[1] == "SRT-PORT":
        return metadata["src_port"] == rule[2]
    if rule[1] == "DST-PORT":
        return metadata["dst_port"] == rule[2]

    if rule[1] == "PROCESS-NAME":
        return EqualFold(metadata["ProcessName"], rule[2])
    if rule[1] == "PROCESS-PATH":
        return EqualFold(metadata["ProcessPath"], rule[2])

    return rule[1] == "MATCH"


# return: Proxy
def ruleAdapter(proxies, rule):
    proxy = proxies[rule[2] if rule[1] == "MATCH" else rule[3]]
    proxy["ProxyAdapter"]["SupportUDP"] = "disable-udp" not in rule[4]
    return proxy


def setMetadata(ctx, metadata, k, v=nil, *args, **kwargs):
    if "function" in type(v):  # 也可能是 builtin_function_or_method
        args = [metadata[x] if x in metadata else x for x in args] if args else metadata
        v = v(*args, **kwargs)

    if v != nil:
        metadata[k] = v
    else:
        v = metadata[k]

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
        "IP" in rule[1]
        and "no-resolve" not in rule[4]
        and metadata["host"] != ""
        and metadata["dst_ipp"] == nil
    )


# reimplement ctx.rule_providers.match(metadata) => boolean
# return: "Policy", "original_rule_string"
#
# See: https://github.com/Dreamacro/clash/blob/master/tunnel/tunnel.go
def match(ctx, metadata):
    proxies = {
        p.name: {
            "ProxyAdapter": {"Name": p.name},
            "history": {"Time": time.now(), "Delay": p.delay},
            "alive": p.alive,
        }
        for p in ctx.proxy_providers["default"]
    }
    setMetadata(ctx, metadata, "dst_ip")
    setMetadata(ctx, metadata, "src_ip")

    resolved = False
    processFound = False

    for rule in RULES:
        if not resolved and shouldResolveIP(metadata, rule):
            setMetadata(ctx, metadata, "dst_ip", ctx.resolve_ip, "host")
            resolved = True

        if not processFound and "PROCESS" in rule[1]:
            processFound = True
            setMetadata(ctx, metadata, "ProcessPath", ctx.resolve_process_name)

        if ruleMatch(metadata, rule):
            adapter, ok, _ = ruleAdapter(proxies, rule).values()
            if not ok:
                continue
            if EqualFold(metadata["network"], "udp") and not adapter["SupportUDP"]:
                continue
            return adapter["Name"], rule[0]

    return "DIRECT", nil


# See: https://github.com/Dreamacro/clash/wiki/Premium:-Scripting
# See: https://lancellc.gitbook.io/clash/clash-config-file/script
def main(ctx, metadata):
    _, rule = match(ctx, metadata)
    if rule != nil:
        out = [
            "[{0}]".format(metadata["network"].upper()),
            "type=" + metadata["type"],
            "host=" + metadata["host"],
            "src={0}:{1}".format(metadata["src_ip"], metadata["src_port"]),
            "dst={0}:{1}".format(metadata["dst_ip"], metadata["dst_port"]),
        ]
        ctx.log("{0} | {1}".format(" ".join(out), rule))
    return _
