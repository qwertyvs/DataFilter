"""
DataFilter is a library written on Python used to check data for presence of web vulnerabilities exploitation

For full documentation, see the README.MD file in the project's GitHub repository
Link to repository: https://github.com/qwertyvs/DataFilter
"""

import regex as re, html, unicodedata, hashlib
from time import time_ns
from urllib.parse import unquote_plus

#(redefine these variables inside code depending on cpu) max time to process pattern in seconds
sqli_pattern_time=0.1
ssti_pattern_time=0.1
xss_pattern_time=0.2

def set_sqli_timeout(value: float) -> None:
    """set_sqli_timeout sets global param sqli_pattern_time

    :param value: new sqli_pattern_time
    :type value: float
    """
    global sqli_pattern_time
    if value > 0:
        sqli_pattern_time = value
    else:
        raise DataFilterException("Invalid sqli timeout")

def set_ssti_timeout(value: float) -> None:
    """set_ssti_timeout sets global param ssti_pattern_time

    :param value: new ssti_pattern_time
    :type value: float
    """
    global ssti_pattern_time
    if value > 0:
        ssti_pattern_time = value
    else:
        raise DataFilterException("Invalid ssti timeout")

def set_xss_timeout(value: float) -> None:
    """set_xss_timeout sets global param xss_pattern_time

    :param value: new xss_pattern_time
    :type value: float
    """
    global xss_pattern_time
    if value > 0:
        xss_pattern_time = value
    else:
        raise DataFilterException("Invalid xss timeout")

#Groups of symbols for quick allowed symbols array assembling
symbolsDict = {
    "ascii_lowercase": "abcdefghijklmnopqrstuvwxyz",
    "ascii_uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ascii": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "numbers": "1234567890",
    "special": "!@#$%^&*()_-+=:;<>,.?/*",
    "all": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+=:;<>,.?/*",
}

#Often used sql keywords
_SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "replace", "truncate",
    "create", "alter", "drop", "rename", "grant", "revoke", "use",
    "describe", "desc", "show", "explain",

    "from", "where", "having", "group by", "order by", "limit", "offset",
    "top", "fetch", "into", "values", "returning", "union", "union all",
    "intersect", "except", "distinct", "case", "when", "then", "else", "end",

    "and", "or", "not", "xor", "like", "ilike", "rlike", "regexp", "similar to",
    "in", "exists", "all", "any", "between", "is", "null", "is null",
    "is not null", "=", "==", "!=", "<>", ">", "<", ">=", "<=",

    "--", "#", "/*", "*/", ";", "-- ", "# ",

    "cast", "convert", "concat", "concat_ws", "group_concat", "string_agg",
    "substr", "substring", "left", "right", "mid", "instr", "locate",
    "length", "char_length", "len", "upper", "lower", "trim", "ltrim", "rtrim",
    "replace", "replace(", "ascii", "char", "chr", "hex", "unhex",

    "+", "-", "*", "/", "%", "mod", "power", "floor", "ceil",

    "exec", "execute", "sp_executesql", "execute immediate", "prepare",
    "deallocate", "execute immediate", "declare", "set", "select into",
    "openrowset", "opendatasource", "openquery", "bulk insert", "bcp",

    "version", "@@version", "version()", "user()", "current_user", "session_user",
    "system_user", "@@hostname", "@@datadir", "@@identity", "@@rowcount",
    "database()", "schema_name", "schema()", "database", "schema",

    "sleep", "benchmark", "load_file", "into outfile", "into dumpfile",
    "information_schema", "performance_schema", "mysql.user", "found_rows",
    "updatexml", "extractvalue", "group_concat", "benchmark(", "sleep(",

    "pg_sleep", "pg_read_file", "pg_ls_dir", "pg_read_binary_file",
    "pg_shadow", "pg_roles", "pg_database", "pg_user", "pg_catalog", "current_database",

    "xp_cmdshell", "sp_msforeachdb", "sp_msforeachtable", "xp_dirtree",
    "xp_availablemedia", "xp_regread", "xp_regwrite", "sp_oacreate",
    "sp_oamethod", "sp_oaputfile", "sp_configure", "master..", "sysobjects",
    "sysdatabases", "information_schema.tables", "sys.tables", "sys.schemas",
    "bulkadmin", "dbcc", "OPENROWSET", "OPENDATASOURCE", "xp_subdirs",

    "dbms_lock.sleep", "dbms_pipe.receive_message", "dbms_output", "utl_http.request",
    "utl_file", "utl_file.fopen", "all_users", "dba_users", "user_users",
    "v$version", "v$instance", "xmltype", "extractvalue", "updatexml",
    "to_char", "to_date", "rownum", "connect by", "sys.dba_users",

    "sqlite_master", "pragma", "attach", "detach", "load_extension",

    "into outfile", "into dumpfile", "load_file(", "xp_cmdshell", "shell",
    "cmd.exe", "powershell", "wget", "curl", "ftp", "into incremental", "outfile",

    "xmltype", "extractvalue", "updatexml", "xpath", "json_extract", "jsonb_extract_path",
    "jsonb_each", "json_each", "jsonb_each_text",

    "information_schema.columns", "information_schema.tables",
    "information_schema.routines", "information_schema.schemata",
    "pg_catalog.pg_tables", "pg_catalog.pg_roles", "all_tables", "dba_tables",

    "inet_server_addr", "inet_server_port", "version()", "session_user()",
    "current_user()", "user()", "database()", "schema()", "schema_name()",

    "count(", "sum(", "avg(", "min(", "max(",

    "sp_tables", "sp_columns", "sp_help", "sp_helptext", "sp_who", "sp_who2",
    "sp_password", "sp_addsrvrolemember", "sp_addlinkedserver",

    "grant", "revoke", "create user", "alter user", "drop user", "create role",
    "dba_", "all_", "role_", "privileges", "has_privilege",

    "concat(", "group_concat(", "string_agg(", "regexp_replace", "regexp_like",
    "instr(", "position(", "pg_sleep(", "sleep(", "benchmark(", "waitfor delay",
    "waitfor", "delay", "dbms_lock.sleep(", "utl_http.request(", "utl_inaddr.get_host_address",

    "having", "limit", "offset", "order", "by", "group", "procedure", "function",
    "trigger", "triggered", "cursor", "open", "fetch", "close", "loop", "if", "elsif",
    "elsif", "else", "end", "case", "while", "for", "begin", "declare", "exception",

    "||", "+", "concat", "concat_ws", "0x", "0x", "/*", "*/", "--", "#",

    "unionselect", "union all select", "union allselect", "unionselect", "union--", "union/*",
    "sleep(", "benchmark(", "benchmark(", "intooutfile", "intodumpfile", "intooutfile(",

    "xmlserialize", "xmlagg", "db2.", "teradata", "tdg", "sysibm", "qsys2", "syscat",
    "SYSDUMMY1", "sysobjects", "syscolumns", "syscomments", "sys.sql_modules",

    "passwd", "password", "pwd", "hash", "salt", "credit_card", "ssn", "social_security_number",

    "load_file(", "openrowset(", "xp_cmdshell(", "sp_oacreate(", "sp_oamethod(", 
    
    "mysql.user", "pg_shadow", "pg_user", "dba_users", "all_users", "user_users",
    "information_schema", "performance_schema", "pg_catalog", "v$session", "v$instance",

    "extractvalue(", "updatexml(", "xmlquery(", "xmltable(",

    "hex(", "unhex(", "base64_decode(", "from_base64(", "to_base64(", "decode(",

    "msdb.dbo.backupset", "msdb.dbo.restorefile", "msdb", "master.dbo", "dba_tables", "all_tables",

    "xp_cmdshell", "xp_dirtree", "xp_regread", "xp_regwrite", "xp_subdirs", "openquery", "openrowset",

    "selecting", "selection", "selected", "dropbox", "updateable"
]

#SQLI regex
_SQLI_FILTERS = {
    "sql_comment": re.compile(r"(--|#)(?!\S)", re.IGNORECASE),
    "sql_comment_multi": re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
    "tautology_numeric": re.compile(r"(?:'|\")?\s*or\s+1\s*=\s*1\b", re.IGNORECASE),
    "tautology_string": re.compile(r"(?:'|\")\s*or\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    "union_select": re.compile(r"\bunion\b\s*(all\s*)?\bselect\b", re.IGNORECASE),
    "stacked_query": re.compile(r";\s*(select|insert|update|delete|drop|create|alter|exec|declare)\b", re.IGNORECASE),
    "time_based": re.compile(r"\b(sleep|pg_sleep|benchmark)\s*\(", re.IGNORECASE),
    "hex_or_char": re.compile(r"\b0x[0-9a-f]+\b|\bchar\s*\(|\bchr\s*\(", re.IGNORECASE),
    "always_true_like": re.compile(r"(?:(?:'|\")\s*=\s*(?:'|\"))|(?:'\s*or\s*'x'='x')", re.IGNORECASE),
    "sql_keyword_used": re.compile(r"\b(" + "|".join(map(re.escape, _SQL_KEYWORDS)) + r")\b", re.IGNORECASE),
    "logical_expression": re.compile(r"\b(or|and)\b\s+[^=<>]+\s*(=|>|<)", re.IGNORECASE)
}

#SSTI regex
_SSTI_FILTERS = {
    "template_delimiters": re.compile(r'(?s)(\{\{\{.*?\}\}\}|\{\{.*?\}\}|\{\%.*?\%\}|<%.*?%>|\$!?\{.*?\}|\#\{.*?\}|\<\#.*?\>)',re.IGNORECASE),
    "template_math": re.compile(r'(?s)\{\{[^}]*[+\-*/%]\s*[^}]*\}\}|\$\{[^}]*[+\-*/%]\s*[^}]*\}|\<%[^%]*[+\-*/%][^%]*%>', re.IGNORECASE),
    "template_filters": re.compile(r'(?i)\|\s*(?:safe|join|attr|map|select|system|sort|replace|tojson|from_json|from_envvar|from_env|json_encode|exec)\b'),
    "python_magic_attrs": re.compile(r'(?i)(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|__dict__|__init__|__base__)\b'),
    "python_magic_via_attr_or_index": re.compile(r'(?i)(?:\|\s*attr\s*\(|attr\s*\(\s*[\'\"][^\'\"]{2,}[\'\"]\s*\)|\[\s*[\'\"][^\'\"]{2,}[\'\"]\s*\]\s*(?:\.\s*\w+)? )'),
    "escaped_underscore_sequences": re.compile(r'(?i)(?:%5f|\\x5f|\\u005f|&#95;|\\u00_?5f)'),
    "obfuscated_keywords": re.compile(r'(?i)(?:' +
        r'c(?:[\W\\x5f%]|_)*l(?:[\W\\x5f%]|_)*a(?:[\W\\x5f%]|_)*s(?:[\W\\x5f%]|_)*s|' +
        r'm(?:[\W\\x5f%]|_)*r(?:[\W\\x5f%]|_)*o|' +
        r'g(?:[\W\\x5f%]|_)*l(?:[\W\\x5f%]|_)*o(?:[\W\\x5f%]|_)*b(?:[\W\\x5f%]|_)*a(?:[\W\\x5f%]|_)*l(?:[\W\\x5f%]|_)*s|' +
        r'b(?:[\W\\x5f%]|_)*u(?:[\W\\x5f%]|_)*i(?:[\W\\x5f%]|_)*l(?:[\W\\x5f%]|_)*t(?:[\W\\x5f%]|_)*i(?:[\W\\x5f%]|_)*n(?:[\W\\x5f%]|_)*s' +
        r')',re.IGNORECASE),
    "python_danger_calls": re.compile(r'(?i)\b(?:os\s*\.\s*popen|os\s*\.\s*system|os\s*\.\s*environ|subprocess(?:\s*\.|s*\()|eval\s*\(|exec\s*\(|open\s*\(|__import__\s*\()',re.IGNORECASE | re.DOTALL),
    "jinja_cycler_chain": re.compile(r'(?i)cycler\.__init__\.__globals__', re.IGNORECASE),
    "file_and_include_ops": re.compile(r'(?i)(?:File\.read\s*\(|(?:include|#include)\s*\(|\bFile\.read\b|\.read\(\s*\)|\bopen\s*\()\b',re.IGNORECASE),
    "base64_and_eval": re.compile(r'(?i)(?:base64\.urlsafe_b64decode|base64\.b64decode|b64decode|urlsafe_b64decode|from_base64).{0,200}(?:eval|exec|popen|__import__)',re.IGNORECASE | re.DOTALL),
    "freemarker_eval_new": re.compile(r'(?i)\?\s*(?:eval|new|c)\b', re.IGNORECASE),
    "freemarker_comment": re.compile(r'(?s)<#--.*?-->'),
    "velocity_directive": re.compile(r'(?i)#\s*(?:set|if|foreach|include|evaluate|parse|macro)\b', re.IGNORECASE),
    "velocity_include_call": re.compile(r'(?i)#\s*include\s*\(\s*[\$\w"\'\(\)\+\/\:\.]+\s*\)', re.IGNORECASE),
    "ognl_java": re.compile(r'(?i)@java\.lang\.\w+@', re.IGNORECASE),
    "jsp_erb": re.compile(r'(?s)<%=?\s*.*?\s*%>'),
    "ruby_interp": re.compile(r'(?s)#\{.*?\}'),
    "ognl_expression_ops": re.compile(r'(?i)(?:\+\s*\'\'\+|\'\s*\+\s*1\*|\@java\.lang\.)', re.IGNORECASE),
    "division_by_zero": re.compile(r'/\s*0\b'),
    "combined_delimiter_and_keyword": re.compile(r'(?i)(\{\{|\{\%|\$\{|\#\{|\{\{\{)[^}]{0,200}(?:__\w+__|globals|builtins|popen|system|subprocess|eval|exec)', re.IGNORECASE),
    "percent_or_hex_obfuscation": re.compile(r'(?i)(?:%5f|\\x5f|\\u005f|&#95;|\\u00_?5f)'),
    "delim_with_dot_or_call": re.compile(r'(?i)(\{\{|\$\{|\#\{|\{\%|<%)[^}]{0,200}(?:\.\w+|\()', re.IGNORECASE),
}

#XSS regex
_XSS_FILTERS = {
    "script_tag": re.compile(r"<\s*script\b", re.IGNORECASE),
    "javascript_protocol": re.compile(r"java[\x00-\x20]*script\s*:", re.IGNORECASE),
    "on_event_attribute": re.compile(r"\bon[a-z]{2,}\s*=", re.IGNORECASE),
    "dangerous_embed_tag": re.compile(r"<\s*(?:iframe|object|embed)\b", re.IGNORECASE),
    "meta_refresh_js": re.compile(r"<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?\s*refresh[^>]*" r"\burl\s*=\s*['\"]?\s*java[\x00-\x20]*script\s*:", re.IGNORECASE),
    "scriptable_uri": re.compile(r"\b(?:href|src|xlink:href|formaction|action)\s*=\s*['\"]?" r"(?:java[\x00-\x20]*script|data\s*:\s*(?:text/html|image/svg\+xml))", re.IGNORECASE),
    "srcdoc": re.compile(r"\bsrcdoc\s*=", re.IGNORECASE),
    "css_js_url": re.compile(r"url\s*\(\s*['\"]?\s*java[\x00-\x20]*script\s*:", re.IGNORECASE),
    "css_expression": re.compile(r"\bexpression\s*\(", re.IGNORECASE),
    "encoded_script_tag": re.compile(r"&(?:lt|#0*60|#x0*3c)\s*;?\s*script\b", re.IGNORECASE),
    "svg_math_tag": re.compile(r"<\s*(?:svg|math)\b", re.IGNORECASE),
    "background": re.compile(r"\sbackground\s*=\s*['\"]?\s*java[\x00-\x20]*script", re.IGNORECASE),
}



class DataFilterException(Exception):
    """DataFilterException internal library exception class"""
    def __init__(self, text: str = "Unknown exception occured"):
        super().__init__(text)

    def __str__(self) -> str:
        return str(self.args[0])



class filterReport:
    """Report structure base, returned by filter functions

    Struction includes:
    data - initial data that was inputted in filter function (string)
    type - check type that was done
    status - code phrase filter function returns:
             OK - no detections
             FOUND - suspicous data found (false positive safeguard)
             DETECTED - dangerous payload found or data is too suspicous (many detections)

    detections - array of names of possibly used sqli strategies:
                 if status is FOUND or DETECTED includes array of strings - short names of detected vulnerabilities usage in data
                 if status is OK - empty array

    issecure - defines if data is secure or dangerous:
               True if data is considered secure
               False if data may be dangerous

    processtime - time taken to process data in ns
    """
    def __init__(self, data: str = "", type: str = "", status: str = "None", detections: list[str] | None = None, issecure: bool = False) -> None:
        self.data = data
        self.type = type
        self.status = status
        self.detections = [] if detections is None else list(detections)
        self.issecure = issecure
        self.processtime = 0



def strSQLICheck(data: str = "", allowedSymbols: str = "") -> filterReport:
    """strSQLICheck checks data for usage of sqli vulnerability

    :param data: data to be checked
    :type data: str
    :param allowedSymbols: string of allowed in data symbols
        if there is a symbol which is not in allowedSymbols, function returns DETECTED status, defaults to ""
    :type allowedSymbols: str, optional
    :raises DataFilterException:
    :return: report, including results of check
    :rtype: filterReport
    """
    try:
        return _strSQLICheck(data = data, allowedSymbols = allowedSymbols)
    except Exception as exp:
        raise DataFilterException(f"Exception occured in strSQLICheck, details: {exp}")



def _strSQLICheck(data: str = "", allowedSymbols: str = "") -> filterReport:
    starttime = time_ns()
    if type(data) != str:
        raise DataFilterException(f"INVALID_INPUT: strSQLICheck expected str as data, instead got {type(data)}")
    
    if type(allowedSymbols) != str:
        raise DataFilterException(f"INVALID_INPUT: strSQLICheck expected str as allowedSymbols, instead got {type(allowedSymbols)}")
    
    if allowedSymbols:
        tempdata = data
        for symbol in allowedSymbols:
            tempdata = tempdata.replace(symbol,"")
        if tempdata:
            return filterReport(data, status = "DETECTED", detections = ["banned_symbol_usage"], issecure = False)

    report = filterReport(data = data, type = "SQLI", status = "OK", issecure = True)

    if "'" in data or '"' in data:
        has_quote = True
        report.detections.append("quotes_usage")
        report.status = "FOUND"
        report.issecure = False
    else:
        has_quote = False

    def match_add(name: str) -> None:
        try:
            if _SQLI_FILTERS[name].search(data, timeout = sqli_pattern_time):
                report.detections.append(name)
                if has_quote:
                    report.issecure = False
                    report.status = "DETECTED"
                else:
                    report.status = "FOUND"
        except TimeoutError:
            if "dos_payload" not in report.detections:
                report.detections.append("dos_payload")
            report.issecure = False
            report.status = "DETECTED"
            return

    for pattern in _SQLI_FILTERS:
        match_add(pattern)

    if len(report.detections) > 1:
        report.issecure = False
        report.status = "DETECTED"
    report.processtime = time_ns() - starttime
    return report



def strSSTICheck(data: str = "", allowedSymbols: str = "") -> filterReport:
    """strSSTICheck checks data for usage of ssti vulnerability

    :param data: data to be checked
    :type data: str
    :param allowedSymbols: string of allowed in data symbols
        if there is a symbol which is not in allowedSymbols, function returns DETECTED status, defaults to ""
    :type allowedSymbols: str, optional
    :raises DataFilterException:
    :return: report, including results of check
    :rtype: filterReport
    """
    try:
        return _strSSTICheck(data = data, allowedSymbols = allowedSymbols)
    except Exception as exp:
        raise DataFilterException(f"Exception occured in strSSTICheck, details: {exp}")



def _strSSTICheck(data: str = "", allowedSymbols: str = "") -> filterReport:
    starttime = time_ns()

    if type(data) != str:
        raise DataFilterException(f"INVALID_INPUT: strSSTICheck expected str as data, instead got {type(data)}")

    if type(allowedSymbols) != str:
        raise DataFilterException(f"INVALID_INPUT: strSSTICheck expected str as allowedSymbols, instead got {type(allowedSymbols)}")
        
    report = filterReport(data = data, type = "SSTI", status = "OK", issecure = True)
        
    seen = set()
    for _ in range(20):
        decoded = data
        decoded = unquote_plus(decoded)
        decoded = html.unescape(decoded)
        try:
            decoded = bytes(decoded, "utf-8").decode("unicode_escape")
        except:
            pass
        decoded = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", "", decoded)
        decoded = unicodedata.normalize("NFKC", decoded)
        h = hashlib.blake2b(decoded.encode("utf-8", "ignore"), digest_size=8).digest()
        if h in seen:
            break
        seen.add(h)
        if decoded == data:
            break
        data = decoded

    if allowedSymbols:
        tempdata = data
        for symbol in allowedSymbols:
            tempdata = tempdata.replace(symbol, "")
        if tempdata:
            return filterReport(data, status = "DETECTED", detections = ["banned_symbol_usage"], issecure = False)
            
    def match_add(name: str) -> None:
        try:
            if _SSTI_FILTERS[name].search(data, timeout = ssti_pattern_time):
                report.detections.append(name)
                report.issecure = False
                report.status = "DETECTED"
        except TimeoutError:
            if "dos_payload" not in report.detections:
                report.detections.append("dos_payload")
            report.issecure = False
            report.status = "DETECTED"
            return

    for pattern in _SSTI_FILTERS:
        try:
            match_add(pattern)
        except re.TimeoutError:
            break

    report.processtime = time_ns() - starttime
    return report



def strXSSCheck(data: str = "", allowedSymbols: str = "") -> filterReport:
    """strXSSCheck checks data for usage of xss vulnerability

    :param data: data to be checked
    :type data: str
    :param allowedSymbols: string of allowed in data symbols
        if there is a symbol which is not in allowedSymbols, function returns DETECTED status, defaults to ""
    :type allowedSymbols: str, optional
    :raises DataFilterException:
    :return: report, including results of check
    :rtype: filterReport
    """
    try:
        return _strXSSCheck(data = data, allowedSymbols = allowedSymbols)
    except Exception as exp:
        raise DataFilterException(f"Exception occured in strXSSCheck, details: {exp}")



def _strXSSCheck(data: str = "", allowedSymbols: str = "") -> filterReport:
    starttime = time_ns()

    if type(data) != str:
        raise DataFilterException(f"INVALID_INPUT: strXSSCheck expected str as data, instead got {type(data)}")

    if type(allowedSymbols) != str:
        raise DataFilterException(f"INVALID_INPUT: strXSSCheck expected str as allowedSymbols, instead got {type(allowedSymbols)}")
        
    report = filterReport(data = data, type = "XSS", status = "OK", issecure = True)

    seen = set()
    for _ in range(20):
        decoded = data
        decoded = unquote_plus(decoded)
        decoded = html.unescape(decoded)
        try:
            decoded = bytes(decoded, "utf-8").decode("unicode_escape")
        except:
            pass
        decoded = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", "", decoded)
        decoded = unicodedata.normalize("NFKC", decoded)
        h = hashlib.blake2b(decoded.encode("utf-8", "ignore"), digest_size=8).digest()
        if h in seen:
            break
        seen.add(h)
        if decoded == data:
            break
        data = decoded
    
    if allowedSymbols:
        tempdata = data
        for symbol in allowedSymbols:
            tempdata = tempdata.replace(symbol, "")
        if tempdata:
            return filterReport(data, status = "DETECTED", detections = ["banned_symbol_usage"], issecure = False)

    def match_add(name: str) -> None:
        try:
            if _XSS_FILTERS[name].search(data, timeout = xss_pattern_time):
                report.detections.append(name)
                report.issecure = False
                report.status = "DETECTED"
        except TimeoutError:
            if "dos_payload" not in report.detections:
                report.detections.append("dos_payload")
            report.issecure = False
            report.status = "DETECTED"
            return

    for pattern in _XSS_FILTERS:
        try:
            match_add(pattern)
        except re.TimeoutError:
            break

    report.processtime = time_ns() - starttime
    return report



def strMultCheck(data: str = "", allowedSymbols: str = "", modes: list[str] = ["SQLI", "SSTI", "XSS"]) -> dict:
    """strMultCheck checks data for usage of multiple vulnerabilities listed in modes

    :param data: data to be checked
    :type data: str
    :param allowedSymbols: string of allowed in data symbols
        if there is a symbol which is not in allowedSymbols, function returns DETECTED status, defaults to ""
    :type allowedSymbols: str, optional
    :raises DataFilterException:
    :return: report for each vulnerability check function, total check time, total issecure and status
    :rtype: dict
    """
    try:
        return _strMultCheck(data = data, allowedSymbols = allowedSymbols, modes = modes)
    except Exception as exp:
        raise DataFilterException(f"Exception occured in strMultCheck, details: {exp}")



def _strMultCheck(data: str = "", allowedSymbols: str = "", modes: list[str] = ["SQLI", "SSTI", "XSS"]) -> dict:
    starttime = time_ns()

    for _mode in modes:
        if _mode not in ["SQLI", "SSTI", "XSS"]:
            raise DataFilterException(f"INVALID_INPUT: strMultCheck got unexpected mode {_mode}, expected SSTI, SQLI or XSS")
    
    report = {}
    _check_funcs={"SQLI":strSQLICheck,"SSTI":strSSTICheck,"XSS":strXSSCheck}

    lstatus = ""
    lissecure = True

    for _mode in modes:
        report[_mode] = _check_funcs[_mode](data, allowedSymbols)
        lissecure = False if not report[_mode].issecure else lissecure
        lstatus = "DETECTED" if report[_mode].status == "DETECTED" else "FOUND" if report[_mode].status == "FOUND" else lstatus
    report["total_status"] = lstatus
    report["total_issecure"] = lissecure
    report["total_processtime"] = time_ns() - starttime

    return report
