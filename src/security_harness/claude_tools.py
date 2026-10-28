"""Best-effort impact inference for Claude Code PreToolUse inputs."""
from __future__ import annotations

import os
import posixpath
import re
import shlex
from dataclasses import dataclass

from .agentguard.sensitive_targets import sensitive_write_target
from .domain import Impact

PARSER_VERSION = "claude-tools/1"
_MAX_IMPACTS = 64
_MAX_TARGET = 4096
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_REDIRECTS = {">", ">>", ">|", "&>", "&>>", ">&"}
_SEPARATORS = {";", ";;", "&&", "||", "|", "&", "|&", "(", ")"}
_SHELL_OPERATORS = ("&&", "||", "|&", ";;", ">>", ">|", "&>>", "&>", ">&",
                    ";", "|", "&", "(", ")", ">", "<")
_SHELL_PREFIXES = {"(", ")", "{", "}", "!", "if", "then", "else", "elif", "fi",
                   "do", "done", "while", "until", "for", "case", "select"}


@dataclass(frozen=True)
class ToolFacts:
    impacts: tuple[Impact, ...]
    unparsed: bool
    notes: tuple[str, ...]

    def analysis(self) -> dict:
        return {"parser": PARSER_VERSION, "unparsed": self.unparsed, "notes": list(self.notes)}


def _path(value: str, cwd: str | None, home: str | None) -> str:
    value = value.replace("\\", "/")
    home_dir = (home or os.path.expanduser("~")).replace("\\", "/").rstrip("/")
    if value == "~" or value.startswith("~/"):
        value = home_dir + value[1:]
    elif value == "$HOME" or value.startswith("$HOME/"):
        value = home_dir + value[5:]
    elif value == "${HOME}" or value.startswith("${HOME}/"):
        value = home_dir + value[7:]
    if not value.startswith("/"):
        value = posixpath.join((cwd or os.getcwd()).replace("\\", "/"), value)
    return posixpath.normpath(value)


def _impact(path: str, operation: str, cwd: str | None, home: str | None) -> Impact | None:
    target = _path(path, cwd, home)[:_MAX_TARGET]
    if target in {"/dev/null", "/dev/stdout", "/dev/stderr"} or target.startswith("/dev/fd/"):
        return None
    kind = "credential" if sensitive_write_target(target) else "file"
    return Impact(kind, target, operation)


def derive_tool_facts(tool_name: str, tool_input: dict, *, cwd: str | None = None,
                      home: str | None = None) -> ToolFacts:
    impacts: list[Impact] = []
    notes: list[str] = []
    unparsed = False

    def add(impact: Impact | None) -> None:
        if impact is not None and impact not in impacts and len(impacts) < _MAX_IMPACTS:
            impacts.append(impact)

    def unknown(reason: str) -> None:
        nonlocal unparsed
        unparsed = True
        if reason not in notes:
            notes.append(reason)

    if not isinstance(tool_input, dict):
        return ToolFacts((), True, ("tool_input: expected object",))
    if tool_name in {"Write", "Edit", "MultiEdit", "NotebookEdit", "Read"}:
        field = "notebook_path" if tool_name == "NotebookEdit" else "file_path"
        path = tool_input.get(field)
        if not isinstance(path, str) or not path:
            unknown(f"{tool_name}: missing {field}")
        else:
            add(_impact(path, "read" if tool_name == "Read" else "write", cwd, home))
    elif tool_name == "WebFetch":
        url = tool_input.get("url")
        if not isinstance(url, str) or not url:
            unknown("WebFetch: missing url")
        else:
            impacts.append(Impact("network", url[:_MAX_TARGET], "egress"))
    elif tool_name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str) or not command:
            unknown("Bash: missing command")
            return ToolFacts((), unparsed, tuple(notes))
        for marker, reason in (("$(", "bash: command substitution"), ("`", "bash: backtick substitution"),
                                ("<(", "bash: process substitution"), (">(", "bash: process substitution"),
                                ("<<", "bash: heredoc or herestring")):
            if marker in command:
                unknown(reason)
        command = command.replace("\\\n", " ")
        for line in command.split("\n"):
            try:
                lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
                lexer.whitespace_split = True
                tokens = list(lexer)
            except ValueError:
                unknown("bash: invalid shell quoting")
                try:
                    tokens = shlex.split(line, posix=True)
                except ValueError:
                    continue
            normalized: list[str] = []
            for token in tokens:
                if not token or not all(ch in ";&|()<>" for ch in token):
                    normalized.append(token)
                    continue
                rest = token
                while rest:
                    operator = next((op for op in _SHELL_OPERATORS if rest.startswith(op)), None)
                    if operator is None:
                        unknown("bash: unrecognised shell operator")
                        break
                    normalized.append(operator)
                    rest = rest[len(operator):]
            tokens = normalized
            if any(tokens[i:i + 2] == ["(", ")"] for i in range(len(tokens) - 1)):
                unknown("bash: function or case syntax")
            commands: list[list[str]] = [[]]
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token in _SEPARATORS:
                    commands.append([])
                elif token in _REDIRECTS or (token.isdigit() and i + 1 < len(tokens) and tokens[i + 1] in _REDIRECTS):
                    if token.isdigit():
                        i += 1
                        token = tokens[i]
                    if token == ">&" and i + 1 < len(tokens) and (tokens[i + 1].isdigit() or tokens[i + 1] == "-"):
                        i += 1
                    elif i + 1 < len(tokens):
                        i += 1
                        target = tokens[i]
                        if any(ch in _path(target, cwd, home) for ch in "$*?["):
                            unknown("bash: unresolved write target")
                        add(_impact(target, "write", cwd, home))
                else:
                    commands[-1].append(token)
                i += 1
            for argv in commands:
                if argv and (argv[0] in {"case", "function", "select"} or
                             any(argv[i:i + 2] == ["(", ")"] for i in range(len(argv) - 1))):
                    unknown("bash: function or case syntax")
                if argv and argv[0] == "for":
                    continue
                while argv and argv[0] in _SHELL_PREFIXES:
                    argv.pop(0)
                while argv and _ASSIGNMENT.match(argv[0]):
                    argv.pop(0)
                while argv:
                    name = posixpath.basename(argv[0])
                    if name == "sudo":
                        argv.pop(0)
                        while argv and (argv[0] in {"-E", "-H", "-n", "-S"} or argv[0] in {"-u", "-g", "-p"}):
                            option = argv.pop(0)
                            if option in {"-u", "-g", "-p"} and argv:
                                argv.pop(0)
                    elif name == "env":
                        argv.pop(0)
                        while argv and (argv[0].startswith("-") or _ASSIGNMENT.match(argv[0])):
                            option = argv.pop(0)
                            if option in {"-u", "--unset"} and argv:
                                argv.pop(0)
                    elif name in {"nohup", "time", "command", "exec", "nice"}:
                        argv.pop(0)
                    elif name == "timeout":
                        argv.pop(0)
                        if argv and argv[0].startswith("-"):
                            argv.pop(0)
                        if argv:
                            argv.pop(0)
                    elif name == "xargs":
                        unknown("bash: xargs command inference")
                        argv.pop(0)
                    else:
                        break
                if not argv:
                    continue
                name = posixpath.basename(argv[0])
                args = argv[1:]
                if name in {"eval", "source", ".", "bash", "sh", "zsh", "dash", "ksh", "fish"} and args:
                    unknown("bash: shell or script execution")
                if name in {"python", "python3", "node", "perl", "ruby"} and any(x in {"-c", "-e"} for x in args):
                    unknown("bash: inline code execution")
                if name in {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "ssh", "rsync"}:
                    network_args = [a for a in args if "://" in a or re.match(r"(?:[^/@:]+@)?[^/:]+:.+", a)]
                    if name != "rsync" or network_args:
                        target = next((a for a in args if "://" in a), None) or (network_args[0] if network_args else name)
                        impacts.append(Impact("network", target[:_MAX_TARGET], "egress"))
                if name == "git":
                    sub = 0
                    while sub < len(args):
                        option = args[sub]
                        if option in {"-C", "-c", "--git-dir", "--work-tree"} and sub + 1 < len(args): sub += 2
                        elif option.startswith(("--git-dir=", "--work-tree=")) or option == "--no-pager" or (option.startswith("-") and not option.startswith("--")):
                            sub += 1
                        else: break
                    if sub < len(args) and args[sub] in {"push", "clone", "fetch", "pull", "ls-remote"}:
                        target = next((a for a in args[sub + 1:] if "://" in a or re.match(r"(?:[^/@:]+@)?[^/:]+:.+", a)), "git")
                        impacts.append(Impact("network", target[:_MAX_TARGET], "egress"))
                    elif args[sub:sub + 2] == ["submodule", "update"]:
                        impacts.append(Impact("network", "git", "egress"))
                def non_options(values):
                    return [x for x in values if not x.startswith("-")]
                writes: list[str] = []
                if name == "tee":
                    writes = non_options(args)
                elif name in {"cp", "mv", "install", "ln"}:
                    if "-t" in args:
                        idx = args.index("-t")
                        if idx + 1 < len(args): writes = [args[idx + 1]]
                    else:
                        values = non_options(args)
                        writes = values[-1:]
                elif name == "dd":
                    writes = [x[3:] for x in args if x.startswith("of=") and len(x) > 3]
                elif name in {"touch", "truncate"}:
                    writes = non_options(args)
                elif name == "sed" and any(x == "-i" or x.startswith("--in-place") for x in args):
                    writes = non_options(args)[-1:]
                elif name in {"chmod", "chown"}:
                    values = non_options(args)
                    writes = values[1:]
                if name == "curl":
                    for flag in ("-o", "--output"):
                        if flag in args and args.index(flag) + 1 < len(args):
                            writes.append(args[args.index(flag) + 1])
                    if "-O" in args or "--remote-name" in args:
                        unknown("bash: curl remote output name not resolved")
                if name == "wget":
                    for flag in ("-O", "--output-document"):
                        if flag in args and args.index(flag) + 1 < len(args):
                            writes.append(args[args.index(flag) + 1])
                for path in writes:
                    if any(ch in _path(path, cwd, home) for ch in "$*?["):
                        unknown("bash: unresolved write target")
                    add(_impact(path, "write", cwd, home))
                if name == "scp" and args and ":" not in args[-1]:
                    add(_impact(args[-1], "write", cwd, home))
    unique = list(dict.fromkeys(impacts))
    return ToolFacts(tuple(unique[:_MAX_IMPACTS]), unparsed, tuple(notes))
