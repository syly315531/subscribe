import base64
import re
import sys


def strDecode(s: str, isurl=True):
    s = re.sub('=|\n', '', s)
    missing_padding = len(s) % 4
    if missing_padding != 0:
        s += '=' * (4 - missing_padding)

    print(s,type(s),len(s))
    try:
        if isurl:
            s = base64.urlsafe_b64decode(s)
        else:
            s = bytes(s, 'utf-8') if isinstance(s, str) else s
            s = base64.decodebytes(s)

        if type(s) == bytes:
            # s = str(s, encoding='UTF-8')
            s = s.decode('UTF-8')
    except Exception as e:
        # s = s if type(s)==str else str(s)
        print(e, s)
        sys.exit()
        return {}

    return s


def strEncode(s: str, isurl=True):
    try:
        if isurl:
            s = base64.urlsafe_b64encode(bytes(s, 'utf-8'))
        else:
            s = base64.b64encode(bytes(s, 'utf-8'))

        if type(s) == bytes:
            # s = str(s, 'utf-8')
            s = s.decode('UTF-8')
    except Exception as e:
        print(e, s)
    return s


def is_base64_code(s):
    '''Check s is Base64.b64encode'''
    if not isinstance(s, str) or not s:
        return "params s not string or None"

    _base64_code = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
                    'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
                    '2', '3', '4', '5', '6', '7', '8', '9', '+',
                    '/', '=']
    _base64_code_set = set(_base64_code)  # 转为set增加in判断时候的效率
    # Check base64 OR codeCheck % 4
    code_fail = [i for i in s if i not in _base64_code_set]
    if code_fail or len(s) % 4 != 0:
        return False
    return True


def isBase64(sb):
    '''Check s is Base64.b64encode'''
    try:
        if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception as e:
        print(e)
        return False
