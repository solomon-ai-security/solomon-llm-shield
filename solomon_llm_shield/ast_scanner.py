from __future__ import annotations
from typing import *
import re, json, logging, ast, math, hmac, hashlib, sqlite3, time, uuid, asyncio, collections, operator
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field, asdict
from .constants import *


_RANKING = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"]
_RANKING_VALUES = {"UNDEFINED": 1, "LOW": 3, "MEDIUM": 5, "HIGH": 10}
_CRITERIA = [("SEVERITY", "UNDEFINED"), ("CONFIDENCE", "UNDEFINED")]
_UNDEFINED = "UNDEFINED"
_LOW = "LOW"
_MEDIUM = "MEDIUM"
_HIGH = "HIGH"
_CONFIDENCE_DEFAULT = "UNDEFINED"

_NOSEC_COMMENT = re.compile(r"#\s*nosec:?\s*(?P<tests>[^#]+)?#?")
_NOSEC_COMMENT_TESTS = re.compile(r"(?:(B\d+|[a-z\d_]+),?)+", re.IGNORECASE)

_EXCLUDE_DIRS = (
    ".svn", "CVS", ".bzr", ".hg", ".git",
    "__pycache__", ".tox", ".eggs", "*.egg",
)


# ===========================================================================
# CWE / ISSUE / CONTEXT 
# ===========================================================================

class _Cwe:
    NOTSET = 0
    IMPROPER_INPUT_VALIDATION = 20
    PATH_TRAVERSAL = 22
    OS_COMMAND_INJECTION = 78
    XSS = 79
    BASIC_XSS = 80
    SQL_INJECTION = 89
    CODE_INJECTION = 94
    IMPROPER_WILDCARD_NEUTRALIZATION = 155
    HARD_CODED_PASSWORD = 259
    IMPROPER_ACCESS_CONTROL = 284
    IMPROPER_CERT_VALIDATION = 295
    CLEARTEXT_TRANSMISSION = 319
    INADEQUATE_ENCRYPTION_STRENGTH = 326
    BROKEN_CRYPTO = 327
    INSUFFICIENT_RANDOM_VALUES = 330
    INSECURE_TEMP_FILE = 377
    UNCONTROLLED_RESOURCE_CONSUMPTION = 400
    DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK = 494
    DESERIALIZATION_OF_UNTRUSTED_DATA = 502
    MULTIPLE_BINDS = 605
    IMPROPER_CHECK_OF_EXCEPT_COND = 703
    INCORRECT_PERMISSION_ASSIGNMENT = 732
    INAPPROPRIATE_ENCODING_FOR_OUTPUT_CONTEXT = 838
    MITRE_URL_PATTERN = "https://cwe.mitre.org/data/definitions/%s.html"

    def __init__(self, id: int = 0):
        self.id = id

    def link(self) -> str:
        return "" if self.id == self.NOTSET else self.MITRE_URL_PATTERN % str(self.id)

    def __str__(self):
        return "" if self.id == self.NOTSET else "CWE-%i (%s)" % (self.id, self.link())

    def as_dict(self):
        return {"id": self.id, "link": self.link()} if self.id != self.NOTSET else {}

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return id(self)


class _Issue:
    def __init__(self, severity, cwe=0, confidence=_CONFIDENCE_DEFAULT, text="",
                 ident=None, lineno=None, test_id="", col_offset=-1, end_col_offset=0):
        self.severity = severity
        self.cwe = _Cwe(cwe)
        self.confidence = confidence
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        self.text = text
        self.ident = ident
        self.fname = ""
        self.fdata = None
        self.test = ""
        self.test_id = test_id
        self.lineno = lineno
        self.col_offset = col_offset
        self.end_col_offset = end_col_offset
        self.linerange = []

    def __eq__(self, other):
        f = ["text", "severity", "cwe", "confidence", "fname", "test", "test_id"]
        return all(getattr(self, x) == getattr(other, x) for x in f)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return id(self)

    def filter(self, severity, confidence):
        return (_RANKING.index(self.severity) >= _RANKING.index(severity)
                and _RANKING.index(self.confidence) >= _RANKING.index(confidence))

    def as_dict(self, with_code=True, max_lines=3):
        out = {
            "filename": self.fname, "test_name": self.test, "test_id": self.test_id,
            "issue_severity": self.severity, "issue_cwe": self.cwe.as_dict(),
            "issue_confidence": self.confidence, "issue_text": self.text,
            "line_number": self.lineno, "line_range": self.linerange,
            "col_offset": self.col_offset, "end_col_offset": self.end_col_offset,
        }
        if with_code:
            out["code"] = self.get_code(max_lines=max_lines)
        return out

    def get_code(self, max_lines=3, tabbed=False):
        lines = []
        max_lines = max(max_lines, 1)
        lmin = max(1, (self.lineno or 1) - max_lines // 2)
        lmax = lmin + len(self.linerange) + max_lines - 1
        if self.fname == "<llm_output>" and self.fdata is not None:
            self.fdata.seek(0)
            for _ in range(1, lmin):
                self.fdata.readline()
        tmplt = "%i\t%s" if tabbed else "%i %s"
        for line_no in range(lmin, lmax):
            if self.fname == "<llm_output>" and self.fdata is not None:
                text = self.fdata.readline()
            else:
                text = ""
            if isinstance(text, bytes):
                text = text.decode("utf-8")
            if not len(text):
                break
            lines.append(tmplt % (line_no, text))
        return "".join(lines)


class _Context:
    def __init__(self, context_object=None):
        self._context = context_object if context_object is not None else {}

    @property
    def call_args(self):
        args = []
        if "call" in self._context and hasattr(self._context["call"], "args"):
            for arg in self._context["call"].args:
                if hasattr(arg, "attr"):
                    args.append(arg.attr)
                else:
                    args.append(self._get_literal_value(arg))
        return args

    @property
    def call_args_count(self):
        if "call" in self._context and hasattr(self._context["call"], "args"):
            return len(self._context["call"].args)
        return None

    @property
    def call_function_name(self):
        return self._context.get("name")

    @property
    def call_function_name_qual(self):
        return self._context.get("qualname")

    @property
    def call_keywords(self):
        if "call" in self._context and hasattr(self._context["call"], "keywords"):
            d = {}
            for li in self._context["call"].keywords:
                if hasattr(li.value, "attr"):
                    d[li.arg] = li.value.attr
                else:
                    d[li.arg] = self._get_literal_value(li.value)
            return d
        return None

    @property
    def node(self):
        return self._context.get("node")

    @property
    def string_val(self):
        return self._context.get("str")

    @property
    def statement(self):
        return self._context.get("statement")

    @property
    def function_def_defaults_qual(self):
        defaults = []
        node = self._context.get("node")
        if node and hasattr(node, "args") and hasattr(node.args, "defaults"):
            for d in node.args.defaults:
                defaults.append(_get_qual_attr(d, self._context.get("import_aliases", {})))
        return defaults

    def _get_literal_value(self, literal):
        if isinstance(literal, ast.Constant):
            if isinstance(literal.value, bool):
                return str(literal.value)
            elif literal.value is None:
                return str(literal.value)
            return literal.value
        elif isinstance(literal, ast.List):
            return [self._get_literal_value(li) for li in literal.elts]
        elif isinstance(literal, ast.Tuple):
            return tuple(self._get_literal_value(ti) for ti in literal.elts)
        elif isinstance(literal, ast.Set):
            return {self._get_literal_value(si) for si in literal.elts}
        elif isinstance(literal, ast.Dict):
            return dict(zip(literal.keys, literal.values))
        elif isinstance(literal, ast.Name):
            return literal.id
        return None

    def get_call_arg_value(self, argument_name):
        kw = self.call_keywords
        if kw is not None and argument_name in kw:
            return kw[argument_name]

    def check_call_arg_value(self, argument_name, argument_values=None):
        v = self.get_call_arg_value(argument_name)
        if v is not None:
            if not isinstance(argument_values, list):
                argument_values = list((argument_values,)) if argument_values is not None else []
            if not argument_values:
                return True
            for val in argument_values:
                if v == val:
                    return True
            return False
        return None

    def get_lineno_for_call_arg(self, argument_name):
        if hasattr(self.node, "keywords"):
            for key in self.node.keywords:
                if key.arg == argument_name:
                    return key.value.lineno
        return None

    def get_call_arg_at_position(self, position_num):
        mx = self.call_args_count
        if mx and position_num < mx:
            arg = self._context["call"].args[position_num]
            return getattr(arg, "attr", None) or self._get_literal_value(arg)
        return None

    def is_module_being_imported(self, module):
        return self._context.get("module") == module

    def is_module_imported_exact(self, module):
        return module in self._context.get("imports", [])

    def is_module_imported_like(self, module):
        if "imports" in self._context:
            for imp in self._context["imports"]:
                if module in imp:
                    return True
        return False

    @property
    def filename(self):
        return self._context.get("filename")

    @property
    def file_data(self):
        return self._context.get("file_data")

    @property
    def import_aliases(self):
        return self._context.get("import_aliases")


# ===========================================================================
# UTILITIES 
# ===========================================================================

def _get_attr_qual_name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    elif isinstance(node, ast.Attribute):
        name = f"{_get_attr_qual_name(node.value, aliases)}.{node.attr}"
        return aliases.get(name, name)
    return ""


def _get_call_name(node, aliases):
    if isinstance(node.func, ast.Name):
        val = node.func.id
        return aliases.get(val, val)
    elif isinstance(node.func, ast.Attribute):
        return _get_attr_qual_name(node.func, aliases)
    return ""


def _get_qual_attr(node, aliases):
    if isinstance(node, ast.Attribute):
        try:
            val = node.value.id
            prefix = aliases.get(val, val)
        except Exception:
            prefix = ""
        return f"{prefix}.{node.attr}"
    return ""


def _deepgetattr(obj, attr):
    for key in attr.split("."):
        obj = getattr(obj, key)
    return obj


def _linerange(node):
    if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
        return list(range(node.lineno, node.end_lineno + 1))
    return [0, 1]


def _concat_string(node, stop=None):
    def _get(n, bits, stop=None):
        if n != stop:
            bits.append(_get(n.left, bits, stop) if isinstance(n.left, ast.BinOp) else n.left)
            bits.append(_get(n.right, bits, stop) if isinstance(n.right, ast.BinOp) else n.right)
    bits = [node]
    while isinstance(node._bandit_parent, ast.BinOp):
        node = node._bandit_parent
    if isinstance(node, ast.BinOp):
        _get(node, bits, stop)
    return (node, " ".join(x.value for x in bits if isinstance(x, ast.Constant) and isinstance(x.value, str)))


def _get_called_name(node):
    func = node.func
    try:
        return func.attr if isinstance(func, ast.Attribute) else func.id
    except AttributeError:
        return ""


def _get_nosec(nosec_lines, context):
    for lineno in context.get("linerange", []):
        nosec = nosec_lines.get(lineno)
        if nosec is not None:
            return nosec
    return None


# ===========================================================================
#  METRICS 
# ===========================================================================

class _Metrics:
    def __init__(self):
        self.data = {"_totals": {"loc": 0, "nosec": 0, "skipped_tests": 0}}
        for rank in _RANKING:
            for criteria in _CRITERIA:
                self.data["_totals"][f"{criteria[0]}.{rank}"] = 0

    def begin(self, fname):
        self.data[fname] = {"loc": 0, "nosec": 0, "skipped_tests": 0}
        self.current = self.data[fname]

    def note_nosec(self, num=1):
        self.current["nosec"] += num

    def note_skipped_test(self, num=1):
        self.current["skipped_tests"] += num

    def count_locs(self, lines):
        def proc(line):
            tmp = line.strip()
            return bool(tmp and not tmp.startswith(b"#") if isinstance(tmp, bytes) else tmp and not tmp.startswith("#"))
        self.current["loc"] += sum(proc(line) for line in lines)

    def count_issues(self, scores):
        self.current.update(self._get_issue_counts(scores))

    def aggregate(self):
        c = collections.Counter()
        for fname in self.data:
            c.update(self.data[fname])
        self.data["_totals"] = dict(c)

    @staticmethod
    def _get_issue_counts(scores):
        issue_counts = {}
        for score in scores:
            for criteria, _ in _CRITERIA:
                for i, rank in enumerate(_RANKING):
                    label = f"{criteria}.{rank}"
                    if label not in issue_counts:
                        issue_counts[label] = 0
                    count = score[criteria][i] // _RANKING_VALUES[rank]
                    issue_counts[label] += count
        return issue_counts


# ===========================================================================
#  BLACKLISTS 
# ===========================================================================

def _build_blacklist_entry(name, bid, cwe, qualnames, message, level="MEDIUM"):
    return {"name": name, "id": bid, "cwe": cwe, "message": message, "qualnames": qualnames, "level": level}


def _gen_call_blacklist():
    sets = []
    sets.append(_build_blacklist_entry("pickle", "B301", _Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
        ["pickle.loads", "pickle.load", "pickle.Unpickler", "dill.loads", "dill.load", "dill.Unpickler",
         "shelve.open", "shelve.DbfilenameShelf", "jsonpickle.decode", "jsonpickle.unpickler.decode",
         "jsonpickle.unpickler.Unpickler", "pandas.read_pickle"],
        "Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue."))
    sets.append(_build_blacklist_entry("marshal", "B302", _Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
        ["marshal.load", "marshal.loads"], "Deserialization with the marshal module is possibly dangerous."))
    sets.append(_build_blacklist_entry("md5", "B303", _Cwe.BROKEN_CRYPTO,
        ["hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD2.new", "Crypto.Hash.MD4.new", "Crypto.Hash.MD5.new",
         "Crypto.Hash.SHA.new", "Cryptodome.Hash.MD2.new", "Cryptodome.Hash.MD4.new", "Cryptodome.Hash.MD5.new",
         "Cryptodome.Hash.SHA.new", "cryptography.hazmat.primitives.hashes.MD5",
         "cryptography.hazmat.primitives.hashes.SHA1"],
        "Use of insecure MD2, MD4, MD5, or SHA1 hash function."))
    sets.append(_build_blacklist_entry("ciphers", "B304", _Cwe.BROKEN_CRYPTO,
        ["Crypto.Cipher.ARC2.new", "Crypto.Cipher.ARC4.new", "Crypto.Cipher.Blowfish.new", "Crypto.Cipher.DES.new",
         "Crypto.Cipher.XOR.new", "Cryptodome.Cipher.ARC2.new", "Cryptodome.Cipher.ARC4.new",
         "Cryptodome.Cipher.Blowfish.new", "Cryptodome.Cipher.DES.new", "Cryptodome.Cipher.XOR.new",
         "cryptography.hazmat.primitives.ciphers.algorithms.ARC4",
         "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
         "cryptography.hazmat.primitives.ciphers.algorithms.CAST5",
         "cryptography.hazmat.primitives.ciphers.algorithms.IDEA",
         "cryptography.hazmat.primitives.ciphers.algorithms.SEED",
         "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES"],
        "Use of insecure cipher {name}. Replace with a known secure cipher such as AES.", "HIGH"))
    sets.append(_build_blacklist_entry("cipher_modes", "B305", _Cwe.BROKEN_CRYPTO,
        ["cryptography.hazmat.primitives.ciphers.modes.ECB"], "Use of insecure cipher mode {name}."))
    sets.append(_build_blacklist_entry("mktemp_q", "B306", _Cwe.INSECURE_TEMP_FILE,
        ["tempfile.mktemp"], "Use of insecure and deprecated function (mktemp)."))
    sets.append(_build_blacklist_entry("eval", "B307", _Cwe.OS_COMMAND_INJECTION,
        ["eval"], "Use of possibly insecure function - consider using safer ast.literal_eval."))
    sets.append(_build_blacklist_entry("mark_safe", "B308", _Cwe.XSS,
        ["django.utils.safestring.mark_safe"], "Use of mark_safe() may expose cross-site scripting vulnerabilities."))
    sets.append(_build_blacklist_entry("urllib_urlopen", "B310", _Cwe.PATH_TRAVERSAL,
        ["urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.URLopener",
         "urllib.request.FancyURLopener", "six.moves.urllib.request.urlopen",
         "six.moves.urllib.request.urlretrieve", "six.moves.urllib.request.URLopener",
         "six.moves.urllib.request.FancyURLopener"],
        "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected."))
    sets.append(_build_blacklist_entry("random", "B311", _Cwe.INSUFFICIENT_RANDOM_VALUES,
        ["random.Random", "random.random", "random.randrange", "random.randint", "random.choice",
         "random.choices", "random.uniform", "random.triangular", "random.randbytes",
         "random.sample", "random.getrandbits"],
        "Standard pseudo-random generators are not suitable for security/cryptographic purposes.", "LOW"))
    sets.append(_build_blacklist_entry("telnetlib", "B312", _Cwe.CLEARTEXT_TRANSMISSION,
        ["telnetlib.Telnet"], "Telnet-related functions are being called. Telnet is considered insecure.", "HIGH"))
    xml_msg = "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with its defusedxml equivalent."
    sets.append(_build_blacklist_entry("xml_bad_cElementTree", "B313", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.etree.cElementTree.parse", "xml.etree.cElementTree.iterparse", "xml.etree.cElementTree.fromstring", "xml.etree.cElementTree.XMLParser"], xml_msg))
    sets.append(_build_blacklist_entry("xml_bad_ElementTree", "B314", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.etree.ElementTree.parse", "xml.etree.ElementTree.iterparse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.XMLParser"], xml_msg))
    sets.append(_build_blacklist_entry("xml_bad_expatreader", "B315", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.sax.expatreader.create_parser"], xml_msg))
    sets.append(_build_blacklist_entry("xml_bad_expatbuilder", "B316", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.dom.expatbuilder.parse", "xml.dom.expatbuilder.parseString"], xml_msg))
    sets.append(_build_blacklist_entry("xml_bad_sax", "B317", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser"], xml_msg))
    sets.append(_build_blacklist_entry("xml_bad_minidom", "B318", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.dom.minidom.parse", "xml.dom.minidom.parseString"], xml_msg))
    sets.append(_build_blacklist_entry("xml_bad_pulldom", "B319", _Cwe.IMPROPER_INPUT_VALIDATION,
        ["xml.dom.pulldom.parse", "xml.dom.pulldom.parseString"], xml_msg))
    sets.append(_build_blacklist_entry("ftplib", "B321", _Cwe.CLEARTEXT_TRANSMISSION,
        ["ftplib.FTP"], "FTP-related functions are being called. FTP is considered insecure.", "HIGH"))
    sets.append(_build_blacklist_entry("unverified_context", "B323", _Cwe.IMPROPER_CERT_VALIDATION,
        ["ssl._create_unverified_context"], "Using an insecure ssl context that does not validate certificates."))
    return {"Call": sets}


def _gen_import_blacklist():
    sets = []
    sets.append(_build_blacklist_entry("import_telnetlib", "B401", _Cwe.CLEARTEXT_TRANSMISSION, ["telnetlib"], "A telnet-related module is being imported. Telnet is insecure.", "HIGH"))
    sets.append(_build_blacklist_entry("import_ftplib", "B402", _Cwe.CLEARTEXT_TRANSMISSION, ["ftplib"], "A FTP-related module is being imported. FTP is insecure.", "HIGH"))
    sets.append(_build_blacklist_entry("import_pickle", "B403", _Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, ["pickle", "cPickle", "dill", "shelve"], "Consider possible security implications associated with {name} module.", "LOW"))
    sets.append(_build_blacklist_entry("import_subprocess", "B404", _Cwe.OS_COMMAND_INJECTION, ["subprocess"], "Consider possible security implications associated with the subprocess module.", "LOW"))
    xml_msg = "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks. Replace {name} with the equivalent defusedxml package."
    sets.append(_build_blacklist_entry("import_xml_etree", "B405", _Cwe.IMPROPER_INPUT_VALIDATION, ["xml.etree.cElementTree", "xml.etree.ElementTree"], xml_msg, "LOW"))
    sets.append(_build_blacklist_entry("import_xml_sax", "B406", _Cwe.IMPROPER_INPUT_VALIDATION, ["xml.sax"], xml_msg, "LOW"))
    sets.append(_build_blacklist_entry("import_xml_expat", "B407", _Cwe.IMPROPER_INPUT_VALIDATION, ["xml.dom.expatbuilder"], xml_msg, "LOW"))
    sets.append(_build_blacklist_entry("import_xml_minidom", "B408", _Cwe.IMPROPER_INPUT_VALIDATION, ["xml.dom.minidom"], xml_msg, "LOW"))
    sets.append(_build_blacklist_entry("import_xml_pulldom", "B409", _Cwe.IMPROPER_INPUT_VALIDATION, ["xml.dom.pulldom"], xml_msg, "LOW"))
    sets.append(_build_blacklist_entry("import_xmlrpclib", "B411", _Cwe.IMPROPER_INPUT_VALIDATION, ["xmlrpc"], "Using {name} to parse untrusted XML data is known to be vulnerable to XML attacks.", "HIGH"))
    sets.append(_build_blacklist_entry("import_httpoxy", "B412", _Cwe.IMPROPER_ACCESS_CONTROL, ["wsgiref.handlers.CGIHandler", "twisted.web.twcgi.CGIScript", "twisted.web.twcgi.CGIDirectory"], "Consider possible security implications associated with {name} module.", "HIGH"))
    sets.append(_build_blacklist_entry("import_pycrypto", "B413", _Cwe.BROKEN_CRYPTO, ["Crypto.Cipher", "Crypto.Hash", "Crypto.IO", "Crypto.Protocol", "Crypto.PublicKey", "Crypto.Random", "Crypto.Signature", "Crypto.Util"], "The pyCrypto library is no longer actively maintained. Consider using pyca/cryptography.", "HIGH"))
    sets.append(_build_blacklist_entry("import_pyghmi", "B415", _Cwe.CLEARTEXT_TRANSMISSION, ["pyghmi"], "An IPMI-related module is being imported. IPMI is considered insecure.", "HIGH"))
    return {"Import": sets, "ImportFrom": sets, "Call": sets}


def _report_blacklist_issue(check, name):
    return _Issue(severity=check.get("level", "MEDIUM"), confidence="HIGH",
                  cwe=check.get("cwe", _Cwe.NOTSET),
                  text=check["message"].replace("{name}", name), ident=name, test_id=check.get("id", "LEGACY"))


def _blacklist_check(context, config):
    node_type = context.node.__class__.__name__
    if node_type == "Call":
        func = context.node.func
        if isinstance(func, ast.Name) and func.id == "__import__":
            if len(context.node.args):
                if isinstance(context.node.args[0], ast.Constant) and isinstance(context.node.args[0].value, str):
                    name = context.node.args[0].value
                else:
                    name = "UNKNOWN"
            else:
                name = ""
        else:
            name = context.call_function_name_qual
            if name in ["importlib.import_module", "importlib.__import__"]:
                if context.call_args_count and context.call_args_count > 0:
                    name = context.call_args[0]
                else:
                    name = context.call_keywords.get("name", "") if context.call_keywords else ""
        for check in config.get(node_type, []):
            for qn in check["qualnames"]:
                if name is not None and name == qn:
                    return _report_blacklist_issue(check, name)
    if node_type.startswith("Import"):
        prefix = ""
        if node_type == "ImportFrom":
            if context.node.module is not None:
                prefix = context.node.module + "."
        for check in config.get(node_type, []):
            for name in context.node.names:
                for qn in check["qualnames"]:
                    if (prefix + name.name).startswith(qn):
                        return _report_blacklist_issue(check, name.name)
    return None


# ===========================================================================
#  PLUGINS — 40 plugins
# ===========================================================================

_RE_WORDS = "(pas+wo?r?d|pass(phrase)?|pwd|token|secrete?)"
_RE_CANDIDATES = re.compile("(^{0}$|_{0}_|^{0}_|_{0}$)".format(_RE_WORDS), re.IGNORECASE)
_SIMPLE_SQL_RE = re.compile(r"(select\s.*from\s|delete\s+from\s|insert\s+into\s.*values[\s(]|update\s.*set\s)", re.IGNORECASE | re.DOTALL)
_FULL_PATH_MATCH = re.compile(r"^(?:[A-Za-z](?=\:)|[\\\/\.])")
_BIDI_CHARACTERS = ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u200f")
_WEAK_HASHES = ("md4", "md5", "sha", "sha1")
_WEAK_CRYPT_HASHES = ("METHOD_CRYPT", "METHOD_MD5", "METHOD_BLOWFISH")


def _plugin_assert_used(context, config):
    for skip in config.get("assert_used", {}).get("skips", []):
        import fnmatch
        if fnmatch.fnmatch(context.filename or "", skip):
            return None
    return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.IMPROPER_CHECK_OF_EXCEPT_COND,
                  text="Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.", test_id="B101")

def _plugin_exec_used(context, config):
    if context.call_function_name_qual == "exec":
        return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="Use of exec detected.", test_id="B102")
    return None

def _plugin_set_bad_file_permissions(context, config):
    import stat
    if "chmod" in (context.call_function_name or ""):
        if context.call_args_count == 2:
            mode = context.get_call_arg_at_position(1)
            if mode is not None and isinstance(mode, int):
                if mode & stat.S_IWOTH or mode & stat.S_IWGRP or mode & stat.S_IXGRP or mode & stat.S_IXOTH:
                    sev = _HIGH if mode & stat.S_IWOTH else _MEDIUM
                    filename = context.get_call_arg_at_position(0) or "NOT PARSED"
                    return _Issue(severity=sev, confidence=_HIGH, cwe=_Cwe.INCORRECT_PERMISSION_ASSIGNMENT,
                                  text="Chmod setting a permissive mask %s on file (%s)." % (oct(mode), filename), test_id="B103")
    return None

def _plugin_hardcoded_bind_all_interfaces(context, config):
    if context.string_val == "0.0.0.0":
        return _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.MULTIPLE_BINDS, text="Possible binding to all interfaces.", test_id="B104")
    return None

def _plugin_hardcoded_password_string(context, config):
    node = context.node
    def _report(value, lineno=None):
        return _Issue(severity=_LOW, confidence=_MEDIUM, cwe=_Cwe.HARD_CODED_PASSWORD, text=f"Possible hardcoded password: '{value}'", lineno=lineno, test_id="B105")
    if isinstance(node._bandit_parent, ast.Assign):
        for targ in node._bandit_parent.targets:
            if isinstance(targ, ast.Name) and _RE_CANDIDATES.search(targ.id):
                return _report(node.value)
            elif isinstance(targ, ast.Attribute) and _RE_CANDIDATES.search(targ.attr):
                return _report(node.value)
    elif isinstance(node._bandit_parent, ast.Dict) and node in node._bandit_parent.keys and _RE_CANDIDATES.search(node.value):
        pos = node._bandit_parent.keys.index(node)
        value_node = node._bandit_parent.values[pos]
        if isinstance(value_node, ast.Constant):
            return _report(value_node.value)
    elif isinstance(node._bandit_parent, ast.Compare):
        comp = node._bandit_parent
        if isinstance(comp.left, ast.Name) and _RE_CANDIDATES.search(comp.left.id):
            if isinstance(comp.comparators[0], ast.Constant) and isinstance(comp.comparators[0].value, str):
                return _report(comp.comparators[0].value)
        elif isinstance(comp.left, ast.Attribute) and _RE_CANDIDATES.search(comp.left.attr):
            if isinstance(comp.comparators[0], ast.Constant) and isinstance(comp.comparators[0].value, str):
                return _report(comp.comparators[0].value)
    return None

def _plugin_hardcoded_password_funcarg(context, config):
    for kw in context.node.keywords:
        if (isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str) and _RE_CANDIDATES.search(kw.arg)):
            return _Issue(severity=_LOW, confidence=_MEDIUM, cwe=_Cwe.HARD_CODED_PASSWORD, text=f"Possible hardcoded password: '{kw.value.value}'", lineno=kw.value.lineno, test_id="B106")
    return None

def _plugin_hardcoded_password_default(context, config):
    defs = [None] * (len(context.node.args.args) - len(context.node.args.defaults))
    defs.extend(context.node.args.defaults)
    for key, val in zip(context.node.args.args, defs):
        if isinstance(key, (ast.Name, ast.arg)):
            if val is None or (isinstance(val, ast.Constant) and val.value is None):
                continue
            if (isinstance(val, ast.Constant) and isinstance(val.value, str) and _RE_CANDIDATES.search(key.arg)):
                return _Issue(severity=_LOW, confidence=_MEDIUM, cwe=_Cwe.HARD_CODED_PASSWORD, text=f"Possible hardcoded password: '{val.value}'", test_id="B107")
    return None

def _plugin_hardcoded_tmp_directory(context, config):
    tmp_dirs = config.get("hardcoded_tmp_directory", {}).get("tmp_dirs", ["/tmp", "/var/tmp", "/dev/shm"])
    if context.string_val and any(context.string_val.startswith(s) for s in tmp_dirs):
        return _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.INSECURE_TEMP_FILE, text="Probable insecure usage of temp file/directory.", test_id="B108")
    return None

def _plugin_try_except_pass(context, config):
    node = context.node
    check_typed = config.get("try_except_pass", {}).get("check_typed_exception", False)
    if len(node.body) == 1:
        if not check_typed and node.type is not None and getattr(node.type, "id", None) != "Exception":
            return None
        if isinstance(node.body[0], ast.Pass):
            return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, text="Try, Except, Pass detected.", test_id="B110")
    return None

def _plugin_try_except_continue(context, config):
    node = context.node
    check_typed = config.get("try_except_continue", {}).get("check_typed_exception", False)
    if len(node.body) == 1:
        if not check_typed and node.type is not None and getattr(node.type, "id", None) != "Exception":
            return None
        if isinstance(node.body[0], ast.Continue):
            return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, text="Try, Except, Continue detected.", test_id="B112")
    return None

def _plugin_request_without_timeout(context, config):
    HTTP_VERBS = {"get", "options", "head", "post", "put", "patch", "delete"}
    HTTPX_ATTRS = {"request", "stream", "Client", "AsyncClient"} | HTTP_VERBS
    qualname = (context.call_function_name_qual or "").split(".")[0]
    if qualname == "requests" and context.call_function_name in HTTP_VERBS:
        if context.check_call_arg_value("timeout") is None:
            return _Issue(severity=_MEDIUM, confidence=_LOW, cwe=_Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, text=f"Call to {qualname} without timeout", test_id="B113")
    if ((qualname == "requests" and context.call_function_name in HTTP_VERBS) or (qualname == "httpx" and context.call_function_name in HTTPX_ATTRS)):
        if context.check_call_arg_value("timeout", "None"):
            return _Issue(severity=_MEDIUM, confidence=_LOW, cwe=_Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, text=f"Call to {qualname} with timeout set to None", test_id="B113")
    return None

def _plugin_flask_debug_true(context, config):
    if context.is_module_imported_like("flask"):
        if (context.call_function_name_qual or "").endswith(".run"):
            if context.check_call_arg_value("debug", "True"):
                return _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.CODE_INJECTION, text="A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger.", lineno=context.get_lineno_for_call_arg("debug"), test_id="B201")
    return None

def _plugin_tarfile_unsafe_members(context, config):
    if context.is_module_imported_exact("tarfile") and "extractall" in (context.call_function_name or ""):
        if "filter" in (context.call_keywords or {}):
            for kw in context.node.keywords:
                if kw.arg == "filter" and isinstance(kw.value, ast.Constant) and kw.value.value == "data":
                    return None
        if "members" in (context.call_keywords or {}):
            for kw in context.node.keywords:
                if kw.arg == "members":
                    if isinstance(kw.value, ast.Call):
                        return _Issue(severity=_LOW, confidence=_LOW, cwe=_Cwe.PATH_TRAVERSAL, text="Usage of tarfile.extractall(members=function(tarfile)). Make sure your function properly discards dangerous members.", test_id="B202")
                    else:
                        return _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.PATH_TRAVERSAL, text="Found tarfile.extractall(members=?) but couldn't identify the type of members.", test_id="B202")
        return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.PATH_TRAVERSAL, text="tarfile.extractall used without any validation. Please check and discard dangerous members.", test_id="B202")
    return None

def _plugin_trojansource(context, config):
    src_data = context.file_data
    if src_data is None:
        return None
    src_data.seek(0)
    raw = src_data.read()
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="replace")
        except Exception:
            return None
    for lineno, line in enumerate(raw.splitlines(), start=1):
        for char in _BIDI_CHARACTERS:
            if char in line:
                col = line.index(char) + 1
                issue = _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.INAPPROPRIATE_ENCODING_FOR_OUTPUT_CONTEXT, text="A Python source file contains bidirectional control characters (%r)." % char, lineno=lineno, col_offset=col, test_id="B613")
                issue.linerange = [lineno]
                return issue
    return None

def _plugin_request_no_cert_validation(context, config):
    HTTP_VERBS = {"get", "options", "head", "post", "put", "patch", "delete"}
    HTTPX_ATTRS = {"request", "stream", "Client", "AsyncClient"} | HTTP_VERBS
    qualname = (context.call_function_name_qual or "").split(".")[0]
    if ((qualname == "requests" and context.call_function_name in HTTP_VERBS) or (qualname == "httpx" and context.call_function_name in HTTPX_ATTRS)):
        if context.check_call_arg_value("verify", "False"):
            return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.IMPROPER_CERT_VALIDATION, text=f"Call to {qualname} with verify=False disabling SSL certificate checks, security issue.", lineno=context.get_lineno_for_call_arg("verify"), test_id="B501")
    return None

def _plugin_ssl_with_bad_version(context, config):
    bad_versions = config.get("ssl_with_bad_version", {}).get("bad_protocol_versions", ["PROTOCOL_SSLv2", "SSLv2_METHOD", "SSLv23_METHOD", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "SSLv3_METHOD", "TLSv1_METHOD", "PROTOCOL_TLSv1_1", "TLSv1_1_METHOD"])
    qualname = context.call_function_name_qual
    if qualname == "ssl.wrap_socket":
        if context.check_call_arg_value("ssl_version", bad_versions):
            return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.BROKEN_CRYPTO, text="ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.", lineno=context.get_lineno_for_call_arg("ssl_version"), test_id="B502")
    elif qualname == "pyOpenSSL.SSL.Context":
        if context.check_call_arg_value("method", bad_versions):
            return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.BROKEN_CRYPTO, text="SSL.Context call with insecure SSL/TLS protocol version identified, security issue.", lineno=context.get_lineno_for_call_arg("method"), test_id="B502")
    return None

def _plugin_ssl_with_no_version(context, config):
    if context.call_function_name_qual == "ssl.wrap_socket":
        if context.check_call_arg_value("ssl_version") is None:
            return _Issue(severity=_LOW, confidence=_MEDIUM, cwe=_Cwe.BROKEN_CRYPTO, text="ssl.wrap_socket call with no SSL/TLS protocol version specified.", test_id="B504")
    return None

def _plugin_ssh_no_host_key_verification(context, config):
    if (context.is_module_imported_like("paramiko") and context.call_function_name == "set_missing_host_key_policy" and context.node.args):
        policy_arg = context.node.args[0]
        policy_val = None
        if isinstance(policy_arg, ast.Attribute):
            policy_val = policy_arg.attr
        elif isinstance(policy_arg, ast.Name):
            policy_val = policy_arg.id
        elif isinstance(policy_arg, ast.Call):
            if isinstance(policy_arg.func, ast.Attribute):
                policy_val = policy_arg.func.attr
            elif isinstance(policy_arg.func, ast.Name):
                policy_val = policy_arg.func.id
        if policy_val in ["AutoAddPolicy", "WarningPolicy"]:
            return _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.IMPROPER_CERT_VALIDATION, text="Paramiko call with policy set to automatically trust the unknown host key.", test_id="B507")
    return None

def _plugin_snmp_insecure_version(context, config):
    if context.call_function_name_qual == "pysnmp.hlapi.CommunityData":
        if context.check_call_arg_value("mpModel", 0) or context.check_call_arg_value("mpModel", 1):
            return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.CLEARTEXT_TRANSMISSION, text="The use of SNMPv1 and SNMPv2 is insecure. You should use SNMPv3 if able.", test_id="B508")
    return None

def _plugin_yaml_load(context, config):
    if not context.is_module_imported_exact("yaml"):
        return None
    qualname = context.call_function_name_qual
    if not isinstance(qualname, str):
        return None
    parts = qualname.split(".")
    func = parts[-1]
    if all(["yaml" in parts, func == "load", not context.check_call_arg_value("Loader", "SafeLoader"), not context.check_call_arg_value("Loader", "CSafeLoader"), not context.get_call_arg_at_position(1) == "SafeLoader", not context.get_call_arg_at_position(1) == "CSafeLoader"]):
        return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.IMPROPER_INPUT_VALIDATION, text="Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().", lineno=context.node.lineno, test_id="B506")
    return None

def _plugin_hashlib_insecure(context, config):
    qualname = context.call_function_name_qual
    if not isinstance(qualname, str):
        return None
    parts = qualname.split(".")
    func = parts[-1]
    keywords = context.call_keywords or {}
    if "hashlib" in parts:
        if func in _WEAK_HASHES:
            if keywords.get("usedforsecurity", "True") == "True":
                return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.BROKEN_CRYPTO, text=f"Use of weak {func.upper()} hash for security. Consider usedforsecurity=False", lineno=context.node.lineno, test_id="B324")
        elif func == "new":
            args = context.call_args
            name = args[0] if args else keywords.get("name")
            if isinstance(name, str) and name.lower() in _WEAK_HASHES:
                if keywords.get("usedforsecurity", "True") == "True":
                    return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.BROKEN_CRYPTO, text=f"Use of weak {name.upper()} hash for security. Consider usedforsecurity=False", lineno=context.node.lineno, test_id="B324")
    elif "crypt" in parts and func in ("crypt", "mksalt"):
        args = context.call_args
        if func == "crypt":
            name = args[1] if len(args) > 1 else keywords.get("salt")
        else:
            name = args[0] if args else keywords.get("method")
        if isinstance(name, str) and name in _WEAK_CRYPT_HASHES:
            return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.BROKEN_CRYPTO, text=f"Use of insecure crypt.{name.upper()} hash function.", lineno=context.node.lineno, test_id="B324")
    return None

def _plugin_weak_cryptographic_key(context, config):
    cfg = config.get("weak_cryptographic_key", {})
    if not cfg:
        cfg = {"weak_key_size_dsa_high": 1024, "weak_key_size_dsa_medium": 2048, "weak_key_size_rsa_high": 1024, "weak_key_size_rsa_medium": 2048, "weak_key_size_ec_high": 160, "weak_key_size_ec_medium": 224}
    func_key_type = {"cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": "DSA", "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": "RSA", "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": "EC", "Crypto.PublicKey.DSA.generate": "DSA", "Crypto.PublicKey.RSA.generate": "RSA", "Cryptodome.PublicKey.DSA.generate": "DSA", "Cryptodome.PublicKey.RSA.generate": "RSA"}
    key_type = func_key_type.get(context.call_function_name_qual)
    if not key_type:
        return None
    arg_pos = {"DSA": 0, "RSA": 1, "EC": 0}
    if key_type in ["DSA", "RSA"]:
        key_size = context.get_call_arg_value("key_size") or context.get_call_arg_at_position(arg_pos[key_type]) or 2048
    else:
        key_size = 224
    if isinstance(key_size, str):
        return None
    sizes = {"DSA": [(cfg["weak_key_size_dsa_high"], _HIGH), (cfg["weak_key_size_dsa_medium"], _MEDIUM)], "RSA": [(cfg["weak_key_size_rsa_high"], _HIGH), (cfg["weak_key_size_rsa_medium"], _MEDIUM)], "EC": [(cfg["weak_key_size_ec_high"], _HIGH), (cfg["weak_key_size_ec_medium"], _MEDIUM)]}
    for size, level in sizes[key_type]:
        if key_size < size:
            return _Issue(severity=level, confidence=_HIGH, cwe=_Cwe.INADEQUATE_ENCRYPTION_STRENGTH, text="%s key sizes below %d bits are considered breakable." % (key_type, size), test_id="B505")
    return None

def _has_shell(context):
    keywords = context.node.keywords
    result = False
    call_kw = context.call_keywords or {}
    if "shell" in call_kw:
        for key in keywords:
            if key.arg == "shell":
                val = key.value
                if isinstance(val, ast.Constant) and isinstance(val.value, (int, float, complex)):
                    result = bool(val.value)
                elif isinstance(val, ast.List):
                    result = bool(val.elts)
                elif isinstance(val, ast.Dict):
                    result = bool(val.keys)
                elif isinstance(val, ast.Name) and val.id in ["False", "None"]:
                    result = False
                elif isinstance(val, ast.Constant):
                    result = val.value
                else:
                    result = True
    return result

def _evaluate_shell_call(context):
    no_formatting = isinstance(context.node.args[0], ast.Constant) and isinstance(context.node.args[0].value, str)
    return _LOW if no_formatting else _HIGH

def _plugin_subprocess_popen_shell_true(context, config):
    cfg = config.get("shell_injection", {})
    if not cfg:
        return None
    if context.call_function_name_qual in cfg.get("subprocess", []):
        if _has_shell(context):
            if len(context.call_args) > 0:
                sev = _evaluate_shell_call(context)
                if sev == _LOW:
                    return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="subprocess call with shell=True seems safe, but may be changed in the future.", lineno=context.get_lineno_for_call_arg("shell"), test_id="B602")
                else:
                    return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="subprocess call with shell=True identified, security issue.", lineno=context.get_lineno_for_call_arg("shell"), test_id="B602")
    return None

def _plugin_subprocess_without_shell(context, config):
    cfg = config.get("shell_injection", {})
    if not cfg:
        return None
    if context.call_function_name_qual in cfg.get("subprocess", []):
        if not _has_shell(context):
            return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="subprocess call - check for execution of untrusted input.", lineno=context.get_lineno_for_call_arg("shell"), test_id="B603")
    return None

def _plugin_any_other_function_shell_true(context, config):
    cfg = config.get("shell_injection", {})
    if not cfg:
        return None
    if context.call_function_name_qual not in cfg.get("subprocess", []):
        if _has_shell(context):
            return _Issue(severity=_MEDIUM, confidence=_LOW, cwe=_Cwe.OS_COMMAND_INJECTION, text="Function call with shell=True parameter identified, possible security issue.", lineno=context.get_lineno_for_call_arg("shell"), test_id="B604")
    return None

def _plugin_start_process_with_shell(context, config):
    cfg = config.get("shell_injection", {})
    if not cfg:
        return None
    if context.call_function_name_qual in cfg.get("shell", []):
        if len(context.call_args) > 0:
            sev = _evaluate_shell_call(context)
            if sev == _LOW:
                return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="Starting a process with a shell: Seems safe, but may be changed in the future.", test_id="B605")
            else:
                return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="Starting a process with a shell, possible injection detected, security issue.", test_id="B605")
    return None

def _plugin_start_process_with_no_shell(context, config):
    cfg = config.get("shell_injection", {})
    if not cfg:
        return None
    if context.call_function_name_qual in cfg.get("no_shell", []):
        return _Issue(severity=_LOW, confidence=_MEDIUM, cwe=_Cwe.OS_COMMAND_INJECTION, text="Starting a process without a shell.", test_id="B606")
    return None

def _plugin_start_process_partial_path(context, config):
    cfg = config.get("shell_injection", {})
    if not cfg or not len(context.call_args):
        return None
    if (context.call_function_name_qual in cfg.get("subprocess", []) or context.call_function_name_qual in cfg.get("shell", []) or context.call_function_name_qual in cfg.get("no_shell", [])):
        node = context.node.args[0]
        if isinstance(node, ast.List) and node.elts:
            node = node.elts[0]
        if (isinstance(node, ast.Constant) and isinstance(node.value, str) and not _FULL_PATH_MATCH.match(node.value)):
            return _Issue(severity=_LOW, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text="Starting a process with a partial executable path", test_id="B607")
    return None

def _plugin_linux_commands_wildcard_injection(context, config):
    cfg = config.get("shell_injection", {})
    if not ("shell" in cfg and "subprocess" in cfg):
        return None
    vulnerable_funcs = ["chown", "chmod", "tar", "rsync"]
    if context.call_function_name_qual in cfg["shell"] or (context.call_function_name_qual in cfg["subprocess"] and context.check_call_arg_value("shell", "True")):
        if context.call_args_count and context.call_args_count >= 1:
            call_argument = context.get_call_arg_at_position(0)
            argument_string = ""
            if isinstance(call_argument, list):
                for li in call_argument:
                    argument_string += f" {li}"
            elif isinstance(call_argument, str):
                argument_string = call_argument
            if argument_string:
                for vf in vulnerable_funcs:
                    if vf in argument_string and "*" in argument_string:
                        return _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.IMPROPER_WILDCARD_NEUTRALIZATION, text="Possible wildcard injection in call: %s" % context.call_function_name_qual, lineno=context.get_lineno_for_call_arg("shell"), test_id="B609")
    return None

def _plugin_paramiko_calls(context, config):
    if context.is_module_imported_like("paramiko"):
        if context.call_function_name in ["exec_command"]:
            return _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.OS_COMMAND_INJECTION, text="Possible shell injection via Paramiko call, check inputs are properly sanitized.", test_id="B601")
    return None

def _plugin_hardcoded_sql_expressions(context, config):
    node = context.node
    wrapper = None
    statement = ""
    str_replace = False
    if isinstance(node._bandit_parent, ast.BinOp):
        out = _concat_string(node, node._bandit_parent)
        wrapper = out[0]._bandit_parent
        statement = out[1]
    elif isinstance(node._bandit_parent, ast.Attribute) and node._bandit_parent.attr in ("format", "replace"):
        statement = node.value
        wrapper = node._bandit_parent._bandit_parent._bandit_parent
        if node._bandit_parent.attr == "replace":
            str_replace = True
    elif hasattr(ast, "JoinedStr") and isinstance(node._bandit_parent, ast.JoinedStr):
        substrings = [child for child in node._bandit_parent.values if isinstance(child, ast.Constant) and isinstance(child.value, str)]
        if substrings and node == substrings[0]:
            statement = "".join(str(child.value) for child in substrings)
            wrapper = node._bandit_parent._bandit_parent
    execute_call = False
    if isinstance(wrapper, ast.Call):
        name = _get_called_name(wrapper)
        execute_call = name in ["execute", "executemany"]
    if _SIMPLE_SQL_RE.search(statement):
        return _Issue(severity=_MEDIUM, confidence=_MEDIUM if execute_call and not str_replace else _LOW, cwe=_Cwe.SQL_INJECTION, text="Possible SQL injection vector through string-based query construction.", test_id="B608")
    return None

def _plugin_jinja2_autoescape_false(context, config):
    qualname = context.call_function_name_qual
    if not isinstance(qualname, str):
        return None
    parts = qualname.split(".")
    func = parts[-1]
    if "jinja2" in parts and func == "Environment":
        for node in ast.walk(context.node):
            if isinstance(node, ast.keyword):
                if getattr(node, "arg", None) == "autoescape" and (getattr(node.value, "id", None) == "False" or getattr(node.value, "value", None) is False):
                    return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.CODE_INJECTION, text="Using jinja2 templates with autoescape=False is dangerous and can lead to XSS.", test_id="B701")
                if getattr(node, "arg", None) == "autoescape":
                    value = getattr(node, "value", None)
                    if getattr(value, "id", None) == "True" or getattr(value, "value", None) is True:
                        return None
                    elif isinstance(value, ast.Call) and (getattr(value.func, "attr", None) == "select_autoescape" or getattr(value.func, "id", None) == "select_autoescape"):
                        return None
                    else:
                        return _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.CODE_INJECTION, text="Using jinja2 templates with autoescape=False is dangerous and can lead to XSS.", test_id="B701")
        return _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.CODE_INJECTION, text="By default, jinja2 sets autoescape to False. Consider using autoescape=True.", test_id="B701")
    return None

def _plugin_use_of_mako_templates(context, config):
    qualname = context.call_function_name_qual
    if not isinstance(qualname, str):
        return None
    parts = qualname.split(".")
    func = parts[-1]
    if "mako" in parts and func == "Template":
        return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.BASIC_XSS, text="Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks.", test_id="B702")
    return None

def _plugin_logging_config_insecure_listen(context, config):
    if (context.call_function_name_qual == "logging.config.listen" and "verify" not in (context.call_keywords or {})):
        return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.CODE_INJECTION, text="Use of insecure logging.config.listen detected.", test_id="B612")
    return None

def _plugin_pytorch_load(context, config):
    if not context.is_module_imported_exact("torch"):
        return None
    qualname = context.call_function_name_qual
    if qualname in {"torch.load", "torch.serialization.load"}:
        weights_only = context.get_call_arg_value("weights_only")
        if weights_only == "True" or weights_only is True:
            return None
        return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, text="Use of unsafe PyTorch load", test_id="B614", lineno=context.get_lineno_for_call_arg("load"))
    return None

def _plugin_huggingface_unsafe_download(context, config):
    hf_modules = ["transformers", "datasets", "huggingface_hub"]
    if not any(context.is_module_imported_like(m) for m in hf_modules):
        return None
    qualname = context.call_function_name_qual
    if not isinstance(qualname, str):
        return None
    unsafe_patterns = {"from_pretrained": ["transformers"], "load_dataset": ["datasets"], "hf_hub_download": ["huggingface_hub"], "snapshot_download": ["huggingface_hub"], "repository_id": ["huggingface_hub"]}
    parts = qualname.split(".")
    func_name = parts[-1]
    if func_name not in unsafe_patterns:
        return None
    required = unsafe_patterns[func_name]
    if not any(m in parts for m in required):
        return None
    call_node = context._context.get("call")
    if call_node is not None:
        for kw in getattr(call_node, "keywords", []):
            if kw.arg in ("revision", "commit_id") and not isinstance(kw.value, ast.Constant):
                return None
    revision = context.get_call_arg_value("revision")
    commit_id = context.get_call_arg_value("commit_id")
    revision_to_check = revision or commit_id
    if revision_to_check is not None:
        if isinstance(revision_to_check, str):
            rev_str = str(revision_to_check).strip("\"'")
            is_hex = all(c in string.hexdigits for c in rev_str)
            if len(rev_str) >= 7 and is_hex:
                return None
    first_arg = context.get_call_arg_at_position(0)
    if first_arg and isinstance(first_arg, str):
        if first_arg.startswith(("./", "/", "../")):
            return None
    return _Issue(severity=_MEDIUM, confidence=_HIGH, text=f"Unsafe Hugging Face Hub download without revision pinning in {func_name}()", cwe=_Cwe.DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK, lineno=context.get_lineno_for_call_arg(func_name), test_id="B615")

def _plugin_markupsafe_markup_xss(context, config):
    qualname = context.call_function_name_qual
    cfg = config.get("markupsafe_xss", {})
    if qualname not in ("markupsafe.Markup", "flask.Markup"):
        if qualname not in cfg.get("extend_markup_names", []):
            return None
    args = context.node.args
    if not args or isinstance(args[0], ast.Constant):
        return None
    allowed_calls = cfg.get("allowed_calls", [])
    if allowed_calls and isinstance(args[0], ast.Call):
        if _get_call_name(args[0], context.import_aliases or {}) in allowed_calls:
            return None
    return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.XSS, text=f"Potential XSS with ``{qualname}`` detected. Do not use ``{context.call_function_name}`` on untrusted data.", test_id="B704")

def _plugin_django_mark_safe(context, config):
    if context.is_module_imported_like("django.utils.safestring"):
        affected = ["mark_safe", "SafeText", "SafeUnicode", "SafeString", "SafeBytes"]
        if context.call_function_name in affected:
            if context.node.args:
                xss = context.node.args[0]
                if not (isinstance(xss, ast.Constant) and isinstance(xss.value, str)):
                    return _Issue(severity=_MEDIUM, confidence=_HIGH, cwe=_Cwe.BASIC_XSS, text="Potential XSS on mark_safe function.", test_id="B703")
    return None

def _plugin_django_extra_used(context, config):
    if context.call_function_name == "extra":
        return _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.SQL_INJECTION, text="Use of extra potential SQL attack vector.", test_id="B610")
    return None

def _plugin_django_rawsql_used(context, config):
    if context.is_module_imported_like("django.db.models"):
        if context.call_function_name == "RawSQL":
            if context.node.args:
                sql = context.node.args[0]
                if not (isinstance(sql, ast.Constant) and isinstance(sql.value, str)):
                    return _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.SQL_INJECTION, text="Use of RawSQL potential SQL attack vector.", test_id="B611")
    return None


_PLUGIN_REGISTRY: List[Tuple[str, str, List[str], Callable, Optional[str]]] = [
    ("B101", "assert_used", ["Assert"], _plugin_assert_used, "assert_used"),
    ("B102", "exec_used", ["Call"], _plugin_exec_used, None),
    ("B103", "set_bad_file_permissions", ["Call"], _plugin_set_bad_file_permissions, None),
    ("B104", "hardcoded_bind_all_interfaces", ["Str"], _plugin_hardcoded_bind_all_interfaces, None),
    ("B105", "hardcoded_password_string", ["Str"], _plugin_hardcoded_password_string, None),
    ("B106", "hardcoded_password_funcarg", ["Call"], _plugin_hardcoded_password_funcarg, None),
    ("B107", "hardcoded_password_default", ["FunctionDef"], _plugin_hardcoded_password_default, None),
    ("B108", "hardcoded_tmp_directory", ["Str"], _plugin_hardcoded_tmp_directory, "hardcoded_tmp_directory"),
    ("B110", "try_except_pass", ["ExceptHandler"], _plugin_try_except_pass, "try_except_pass"),
    ("B112", "try_except_continue", ["ExceptHandler"], _plugin_try_except_continue, "try_except_continue"),
    ("B113", "request_without_timeout", ["Call"], _plugin_request_without_timeout, None),
    ("B201", "flask_debug_true", ["Call"], _plugin_flask_debug_true, None),
    ("B202", "tarfile_unsafe_members", ["Call"], _plugin_tarfile_unsafe_members, None),
    ("B613", "trojansource", ["File"], _plugin_trojansource, None),
    ("B501", "request_with_no_cert_validation", ["Call"], _plugin_request_no_cert_validation, None),
    ("B502", "ssl_with_bad_version", ["Call"], _plugin_ssl_with_bad_version, "ssl_with_bad_version"),
    ("B504", "ssl_with_no_version", ["Call"], _plugin_ssl_with_no_version, None),
    ("B505", "weak_cryptographic_key", ["Call"], _plugin_weak_cryptographic_key, "weak_cryptographic_key"),
    ("B506", "yaml_load", ["Call"], _plugin_yaml_load, None),
    ("B507", "ssh_no_host_key_verification", ["Call"], _plugin_ssh_no_host_key_verification, None),
    ("B508", "snmp_insecure_version_check", ["Call"], _plugin_snmp_insecure_version, None),
    ("B324", "hashlib", ["Call"], _plugin_hashlib_insecure, None),
    ("B601", "paramiko_calls", ["Call"], _plugin_paramiko_calls, None),
    ("B602", "subprocess_popen_with_shell_equals_true", ["Call"], _plugin_subprocess_popen_shell_true, "shell_injection"),
    ("B603", "subprocess_without_shell_equals_true", ["Call"], _plugin_subprocess_without_shell, "shell_injection"),
    ("B604", "any_other_function_with_shell_equals_true", ["Call"], _plugin_any_other_function_shell_true, "shell_injection"),
    ("B605", "start_process_with_a_shell", ["Call"], _plugin_start_process_with_shell, "shell_injection"),
    ("B606", "start_process_with_no_shell", ["Call"], _plugin_start_process_with_no_shell, "shell_injection"),
    ("B607", "start_process_with_partial_path", ["Call"], _plugin_start_process_partial_path, "shell_injection"),
    ("B608", "hardcoded_sql_expressions", ["Str"], _plugin_hardcoded_sql_expressions, None),
    ("B609", "linux_commands_wildcard_injection", ["Call"], _plugin_linux_commands_wildcard_injection, "shell_injection"),
    ("B610", "django_extra_used", ["Call"], _plugin_django_extra_used, None),
    ("B611", "django_rawsql_used", ["Call"], _plugin_django_rawsql_used, None),
    ("B612", "logging_config_insecure_listen", ["Call"], _plugin_logging_config_insecure_listen, None),
    ("B614", "pytorch_load", ["Call"], _plugin_pytorch_load, None),
    ("B615", "huggingface_unsafe_download", ["Call"], _plugin_huggingface_unsafe_download, None),
    ("B701", "jinja2_autoescape_false", ["Call"], _plugin_jinja2_autoescape_false, None),
    ("B702", "use_of_mako_templates", ["Call"], _plugin_use_of_mako_templates, None),
    ("B703", "django_mark_safe", ["Call"], _plugin_django_mark_safe, None),
    ("B704", "markupsafe_markup_xss", ["Call"], _plugin_markupsafe_markup_xss, "markupsafe_xss"),
]

_DEFAULT_CONFIG: Dict[str, Any] = {
    "assert_used": {"skips": []},
    "hardcoded_tmp_directory": {"tmp_dirs": ["/tmp", "/var/tmp", "/dev/shm"]},
    "try_except_pass": {"check_typed_exception": False},
    "try_except_continue": {"check_typed_exception": False},
    "ssl_with_bad_version": {"bad_protocol_versions": ["PROTOCOL_SSLv2", "SSLv2_METHOD", "SSLv23_METHOD", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "SSLv3_METHOD", "TLSv1_METHOD", "PROTOCOL_TLSv1_1", "TLSv1_1_METHOD"]},
    "weak_cryptographic_key": {"weak_key_size_dsa_high": 1024, "weak_key_size_dsa_medium": 2048, "weak_key_size_rsa_high": 1024, "weak_key_size_rsa_medium": 2048, "weak_key_size_ec_high": 160, "weak_key_size_ec_medium": 224},
    "shell_injection": {"subprocess": ["subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.run"], "shell": ["os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4", "popen2.popen2", "popen2.popen3", "popen2.popen4", "popen2.Popen3", "popen2.Popen4", "commands.getoutput", "commands.getstatusoutput", "subprocess.getoutput", "subprocess.getstatusoutput"], "no_shell": ["os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp", "os.execvpe", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe", "os.startfile"]},
    "markupsafe_xss": {"extend_markup_names": [], "allowed_calls": []},
}


# ===========================================================================
#  AST VISITOR 
# ===========================================================================

class _ASTVisitor:
    def __init__(self, fname, fdata, testset, nosec_lines, metrics, config, debug=False):
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.scores = {"SEVERITY": [0] * len(_RANKING), "CONFIDENCE": [0] * len(_RANKING)}
        self.depth = 0
        self.fname = fname
        self.fdata = fdata
        self.testset = testset
        self.config = config
        self.imports: Set[str] = set()
        self.import_aliases: Dict[str, str] = {}
        self.metrics = metrics
        self.results: List[_Issue] = []
        self.context: dict = {}

    def _run_tests(self, raw_context, checktype):
        scores = {"SEVERITY": [0] * len(_RANKING), "CONFIDENCE": [0] * len(_RANKING)}
        tests = self.testset.get(checktype, [])
        for test_fn, test_id, test_name, config_key in tests:
            import copy as _copy
            temp_context = _copy.copy(raw_context)
            context = _Context(temp_context)
            try:
                if config_key:
                    result = test_fn(context, self.config.get(config_key, {}))
                else:
                    result = test_fn(context, self.config)
                if result is not None:
                    nosec_tests = self._get_nosecs(temp_context, result)
                    if isinstance(temp_context.get("filename"), bytes):
                        result.fname = temp_context["filename"].decode("utf-8")
                    else:
                        result.fname = temp_context.get("filename", "")
                    result.fdata = temp_context.get("file_data")
                    if result.lineno is None:
                        result.lineno = temp_context.get("lineno")
                    if result.linerange == []:
                        result.linerange = temp_context.get("linerange", [])
                    if result.col_offset == -1:
                        result.col_offset = temp_context.get("col_offset", -1)
                    result.end_col_offset = temp_context.get("end_col_offset", 0)
                    result.test = test_name
                    if result.test_id == "":
                        result.test_id = test_id
                    if nosec_tests is not None:
                        if not nosec_tests:
                            self.metrics.note_nosec()
                            continue
                        if result.test_id in nosec_tests:
                            self.metrics.note_skipped_test()
                            continue
                    self.results.append(result)
                    sev = _RANKING.index(result.severity)
                    scores["SEVERITY"][sev] += _RANKING_VALUES[result.severity]
                    con = _RANKING.index(result.confidence)
                    scores["CONFIDENCE"][con] += _RANKING_VALUES[result.confidence]
                else:
                    nosec_tests = self._get_nosecs(temp_context)
                    if nosec_tests and test_id in nosec_tests:
                        pass
            except Exception:
                pass
        return scores

    def _get_nosecs(self, context, test_result=None):
        nosec_tests: Set[str] = set()
        base_tests = self.nosec_lines.get(test_result.lineno, None) if test_result else None
        context_tests = _get_nosec(self.nosec_lines, context)
        if base_tests is None and context_tests is None:
            return None
        if base_tests is not None:
            nosec_tests.update(base_tests)
        if context_tests is not None:
            nosec_tests.update(context_tests)
        return nosec_tests

    def _update_scores(self, scores):
        for score_type in self.scores:
            self.scores[score_type] = list(map(operator.add, self.scores[score_type], scores[score_type]))

    def _pre_visit(self, node):
        self.context = {}
        self.context["imports"] = self.imports
        self.context["import_aliases"] = self.import_aliases
        if hasattr(node, "lineno"):
            self.context["lineno"] = node.lineno
        if hasattr(node, "col_offset"):
            self.context["col_offset"] = node.col_offset
        if hasattr(node, "end_col_offset"):
            self.context["end_col_offset"] = node.end_col_offset
        self.context["node"] = node
        self.context["linerange"] = _linerange(node)
        self.context["filename"] = self.fname
        self.context["file_data"] = self.fdata
        self.depth += 1
        return True

    def _visit(self, node):
        name = node.__class__.__name__
        method = "visit_" + name
        visitor = getattr(self, method, None)
        if visitor is not None:
            visitor(node)
        else:
            self._update_scores(self._run_tests(self.context, name))

    def _post_visit(self, node):
        self.depth -= 1

    def visit_FunctionDef(self, node):
        self.context["function"] = node
        self._update_scores(self._run_tests(self.context, "FunctionDef"))

    def visit_Call(self, node):
        self.context["call"] = node
        qualname = _get_call_name(node, self.import_aliases)
        name = qualname.split(".")[-1]
        self.context["qualname"] = qualname
        self.context["name"] = name
        self._update_scores(self._run_tests(self.context, "Call"))

    def visit_Import(self, node):
        for nodename in node.names:
            if nodename.asname:
                self.import_aliases[nodename.asname] = nodename.name
            self.imports.add(nodename.name)
            self.context["module"] = nodename.name
        self._update_scores(self._run_tests(self.context, "Import"))

    def visit_ImportFrom(self, node):
        module = node.module
        if module is None:
            return self.visit_Import(node)
        for nodename in node.names:
            if nodename.asname:
                self.import_aliases[nodename.asname] = module + "." + nodename.name
            else:
                self.import_aliases[nodename.name] = module + "." + nodename.name
            self.imports.add(module + "." + nodename.name)
            self.context["module"] = module
            self.context["name"] = nodename.name
        self._update_scores(self._run_tests(self.context, "ImportFrom"))

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.visit_Str(node)
        elif isinstance(node.value, bytes):
            self.visit_Bytes(node)

    def visit_Str(self, node):
        self.context["str"] = node.value
        if not isinstance(node._bandit_parent, ast.Expr):
            self.context["linerange"] = _linerange(node._bandit_parent)
            self._update_scores(self._run_tests(self.context, "Str"))

    def visit_Bytes(self, node):
        self.context["bytes"] = node.value
        if not isinstance(node._bandit_parent, ast.Expr):
            self.context["linerange"] = _linerange(node._bandit_parent)
            self._update_scores(self._run_tests(self.context, "Bytes"))

    def visit_Assert(self, node):
        self._update_scores(self._run_tests(self.context, "Assert"))

    def visit_ExceptHandler(self, node):
        self._update_scores(self._run_tests(self.context, "ExceptHandler"))

    def generic_visit(self, node):
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                max_idx = len(value) - 1
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        if idx < max_idx:
                            item._bandit_sibling = value[idx + 1]
                        else:
                            item._bandit_sibling = None
                        item._bandit_parent = node
                        if self._pre_visit(item):
                            self._visit(item)
                            self.generic_visit(item)
                            self._post_visit(item)
            elif isinstance(value, ast.AST):
                value._bandit_sibling = None
                value._bandit_parent = node
                if self._pre_visit(value):
                    self._visit(value)
                    self.generic_visit(value)
                    self._post_visit(value)

    def process(self, data):
        f_ast = ast.parse(data)
        self.generic_visit(f_ast)
        self.context = {"file_data": self.fdata, "filename": self.fname, "lineno": 0, "linerange": [0, 1], "col_offset": 0}
        self._update_scores(self._run_tests(self.context, "File"))
        return self.scores


def _build_test_set(profile):
    """Build test set from profile — копия логики BanditTestSet._load_tests."""
    tests: Dict[str, list] = {}
    inc = set(profile.get("include", []))
    exc = set(profile.get("exclude", []))
    
    # 1. Регистрация обычных плагинов
    for test_id, name, check_types, func, config_key in _PLUGIN_REGISTRY:
        if inc and test_id not in inc:
            continue
        if test_id in exc:
            continue
        for ct in check_types:
            tests.setdefault(ct, []).append((func, test_id, name, config_key))
            
    # 2. Регистрация черных списков (исправленная логика)
    if "B001" not in exc and (not inc or "B001" in inc):
        call_bl = _gen_call_blacklist()
        import_bl = _gen_import_blacklist()
        
        # Обработка Call черных списков
        for node_type, entries in call_bl.items():
            valid_entries = []
            for entry in entries:
                bid = entry["id"]
                if inc and bid not in inc:
                    continue
                if bid in exc:
                    continue
                valid_entries.append(entry)
            
            if valid_entries:
                # Передаем словарь с правильным ключом node_type
                bl_config = {node_type: valid_entries}
                tests.setdefault(node_type, []).append(
                    (lambda ctx, cfg, _c=bl_config: _blacklist_check(ctx, _c),
                     "B001", "blacklist_calls", None)
                )
                
        # Обработка Import черных списков
        for node_type, entries in import_bl.items():
            valid_entries = []
            for entry in entries:
                bid = entry["id"]
                if inc and bid not in inc:
                    continue
                if bid in exc:
                    continue
                valid_entries.append(entry)
            
            if valid_entries:
                bl_config = {node_type: valid_entries}
                tests.setdefault(node_type, []).append(
                    (lambda ctx, cfg, _c=bl_config: _blacklist_check(ctx, _c),
                     "B001", "blacklist_imports", None)
                )
                
    return tests


# ===========================================================================
#  CODE EXTRACTION & LLM PATTERNS 
# ===========================================================================

_PYTHON_CODE_BLOCK_RE = re.compile(r"```(?:python|py|Python)?\n(.*?)```", re.DOTALL)
_SHELL_CODE_BLOCK_RE = re.compile(r"```(?:bash|sh|shell|zsh)?\n(.*?)```", re.DOTALL)
_SQL_CODE_BLOCK_RE = re.compile(r"```(?:sql|SQL)?\n(.*?)```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")

_PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "Possible prompt injection: 'ignore previous instructions'"),
    (re.compile(r"disregard\s+(all\s+)?prior\s+(instructions|prompts)", re.IGNORECASE), "Possible prompt injection: 'disregard prior instructions'"),
    (re.compile(r"you\s+are\s+now\s+(?:a|an)\s+(?:different|new|jailbroken)", re.IGNORECASE), "Possible prompt injection: identity override attempt"),
    (re.compile(r"(?:reveal|show|print|output)\s+(?:your|the)\s+(?:system|hidden)\s+prompt", re.IGNORECASE), "Possible prompt injection: system prompt extraction attempt"),
    (re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[INST\]|\[/INST\]", re.IGNORECASE), "Possible prompt injection: special token injection"),
]

_SUSPICIOUS_URL_RE = re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1\])", re.IGNORECASE)

_LLM_SECRET_LEAK_PATTERNS = [
    (re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?", re.IGNORECASE), "Possible API key leak in LLM output"),
    (re.compile(r"(?:aws_secret_access_key|aws_access_key_id)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?", re.IGNORECASE), "Possible AWS credential leak in LLM output"),
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", re.IGNORECASE), "Possible GitHub token leak in LLM output"),
    (re.compile(r"(?:sk-)[A-Za-z0-9]{20,}", re.IGNORECASE), "Possible OpenAI API key leak in LLM output"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", re.IGNORECASE), "Private key block detected in LLM output"),
    (re.compile(r"(?:Bearer\s+)[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE), "Possible Bearer token leak in LLM output"),
]



