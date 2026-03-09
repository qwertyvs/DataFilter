"""
DataFilter is a library written on Python used to check data for presence of web vulnerabilities exploitation

For full documentation, see the README.MD file in the project's GitHub repository
Link to repository: https://github.com/qwertyvs/DataFilter
"""

import regex as re, html, unicodedata, hashlib
from time import time_ns
from urllib.parse import unquote

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
    if sqli_pattern_time > 0:
        sqli_pattern_time = value
    else:
        raise DataFilterException("Invalid sqli timeout")

def set_ssti_timeout(value: float) -> None:
    """set_ssti_timeout sets global param ssti_pattern_time

    :param value: new ssti_pattern_time
    :type value: float
    """
    global ssti_pattern_time
    if ssti_pattern_time > 0:
        ssti_pattern_time = value
    else:
        raise DataFilterException("Invalid ssti timeout")

def set_xss_timeout(value: float) -> None:
    """set_xss_timeout sets global param xss_pattern_time

    :param value: new xss_pattern_time
    :type value: float
    """
    global xss_pattern_time
    if xss_pattern_time > 0:
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
    "python_magic_attrs": re.compile(r"__class__|__mro__|__subclasses__|__globals__|__init__"),
    "python_danger_calls": re.compile(r"os\.popen|subprocess|eval\(|exec\(|open\(", re.IGNORECASE),
    "java_runtime": re.compile(r"Runtime\.getRuntime|ProcessBuilder|Class\.forName", re.IGNORECASE),
    "php_exec": re.compile(r"shell_exec|passthru|system\(|exec\(", re.IGNORECASE),
    "node_constructor_rce": re.compile(r"constructor\s*\.\s*constructor", re.IGNORECASE),
    "ruby_eval": re.compile(r"instance_eval|class_eval|Kernel\.", re.IGNORECASE),
    "double_curly": re.compile(r"\{\{.*?\}\}", re.DOTALL),
    "percent_blocks": re.compile(r"\{\%.*?\%\}", re.DOTALL),
    "angle_percent": re.compile(r"<%.*?%>", re.DOTALL),
    "dollar_brace": re.compile(r"\$\{.*?\}", re.DOTALL),
    "hash_brace": re.compile(r"\#\{.*?\}", re.DOTALL),
    "template_filters": re.compile(r"\|\s*(safe|join|attr|map|select|system)", re.IGNORECASE),
    "template_math": re.compile(r"\{\{.*?[\+\-\*/].*?\}\}", re.DOTALL),
    "triple_curly": re.compile(r"\{\{\{.*?\}\}\}", re.DOTALL),
    "freemarker_directive": re.compile(r"<#.*?>", re.DOTALL),
    "dollar_excl_brace": re.compile(r"\$!?\{.*?\}", re.DOTALL),
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

    if allowedSymbols:
        tempdata = data
        for symbol in allowedSymbols:
            tempdata = tempdata.replace(symbol, "")
        if tempdata:
            return filterReport(data, status = "DETECTED", detections = ["banned_symbol_usage"], issecure = False)

    report = filterReport(data = data, type = "SSTI", status = "OK", issecure = True)
            
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

    if allowedSymbols:
        tempdata = data
        for symbol in allowedSymbols:
            tempdata = tempdata.replace(symbol, "")
        if tempdata:
            return filterReport(data, status = "DETECTED", detections = ["banned_symbol_usage"], issecure = False)

    seen = set()
    for i in range(20):
        h = hashlib.blake2b(data.encode('utf-8','ignore'), digest_size=8).digest()
        if h in seen:
            break
        seen.add(h)
        decoded = unquote(data)
        decoded = html.unescape(decoded)
        decoded = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", "", decoded)
        decoded = unicodedata.normalize("NFC", decoded)
        if decoded == data:
            break
        data = decoded

    report = filterReport(data = data, type = "XSS", status = "OK", issecure = True)

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



def strMultCheck(data: str = "", allowedSymbols: str = "", modes: list[str] = ["SQLI", "SSTI", "XSS"]) -> dict[str: ...]:
    """strMultCheck checks data for usage of multiple vulnerabilities listed in modes

    :param data: data to be checked
    :type data: str
    :param allowedSymbols: string of allowed in data symbols
        if there is a symbol which is not in allowedSymbols, function returns DETECTED status, defaults to ""
    :type allowedSymbols: str, optional
    :raises DataFilterException:
    :return: report for each vulnerability check function, total check time, total issecure and status
    :rtype: dict[str: ...]
    """
    try:
        return _strMultCheck(data = data, allowedSymbols = allowedSymbols, modes = modes)
    except Exception as exp:
        raise DataFilterException(f"Exception occured in strMultCheck, details: {exp}")



def _strMultCheck(data: str = "", allowedSymbols: str = "", modes: list[str] = ["SQLI", "SSTI", "XSS"]) -> dict[str: ...]:
    starttime = time_ns()

    for _mode in modes:
        if _mode not in ["SQLI", "SSTI", "XSS"]:
            raise DataFilterException(f"INVALID_INPUT: strMultCheck got unexpected mode {_mode}, expected SSTI, SQLI or XSS")
    
    reports = {}
    _check_funcs={"SQLI":strSQLICheck,"SSTI":strSSTICheck,"XSS":strXSSCheck}

    lstatus = ""
    lissecure = True

    for _mode in modes:
        reports[_mode] = _check_funcs[_mode](data, allowedSymbols)
        lissecure = False if not reports[_mode].issecure else lissecure
        lstatus = "DETECTED" if reports[_mode].status == "DETECTED" else "FOUND" if reports[_mode].status == "FOUND" else lstatus
    reports["total_status"] = lstatus
    reports["total_issecure"] = lissecure
    reports["total_processtime"] = time_ns() - starttime
