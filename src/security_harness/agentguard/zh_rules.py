"""Structural Chinese injection rules (rules-v0.6).

Patterns are built from verb classes x target-noun classes with bounded gaps
rather than memorised phrases. Text is first folded: Traditional -> Simplified
for the characters these rules use, and whitespace between CJK characters is
removed so that "忽 略 指 令" style splitting is still matched.
"""

from __future__ import annotations

import re

# Minimal Traditional->Simplified fold for characters used in the rules (no dependency).
_T2S_PAIRS = (
    "無无 視视 忽忽 記记 過过 繞绕 拋抛 棄弃 撤撤 蓋盖 遵遵 從从 現现 開开 發发 始始 將将 "
    "們们 個个 這这 請请 給给 訴诉 讓让 別别 瞞瞒 執执 運运 讀读 傳传 轉转 帶带 附附 "
    "鑰钥 憑凭 證证 碼码 話话 聊聊 錄录 歷历 史史 環环 變变 數数 統统 啟启 戶户 實实 際际 "
    "規规 則则 範范 準准 設设 定定 務务 題题 內内 容容 對对 關关 閉闭 禁禁 審审 計计 誌志 "
    "確确 認认 檢检 查查 牆墙 殺杀 毒毒 刪删 除除 清清 空空 輸输 出出 複复 說说 顯显 洩泄 "
    "透透 露露 隱隐 藏藏 礙碍 遊游 戲戏 演演 裝装 扮扮 限限 制制 約约 束束 道道 德德 "
    "律律 拒拒 絕绝 應应 該该 須须 時时 調调 用用 載载 單单 據据 庫库 產产 權权 帳账 "
    "號号 郵邮 箱箱 網网 址址 標标 籤签 項项 憶忆 長长 為为 樣样 麼么 會会 寫写 錯错 "
    "誤误 據据 屬属 於于 處处 理理 頁页 檔档 語语 氣气 覺觉 經经 驗验 選选 擇择"
)
_T2S = {pair[0]: pair[1] for pair in _T2S_PAIRS.split() if pair[0] != pair[1]}
_T2S_TABLE = str.maketrans(_T2S)
_CJK_GAP = re.compile(r"(?<=[\u4e00-\u9fff])[ \t\u3000·_\-]+(?=[\u4e00-\u9fff])")


def fold_zh(text: str) -> str:
    return _CJK_GAP.sub("", text.translate(_T2S_TABLE))


G = r"[^。！？!?\n]{0,%d}"  # bounded gap that does not cross a sentence end

OVERRIDE_VERB = (
    r"(?:忽略|无视|忽视|不要理会|不用理会|不必理会|别管|忘记|忘掉|忘了|跳过|绕过|抛开|抛弃|放弃|"
    r"废除|撤销|覆盖|不再遵守|不必遵守|不用遵守|停止遵守|不要遵守|违背|推翻)"
)
QUALIFIER = r"(?:此|这个|该|本|上述|上面|以上|之前|先前|此前|前面|前述|原来|原有|原先|原本|刚才|所有|全部|一切|系统|默认|既定)"
STRONG_TARGET = (
    r"(?:指令|指示|命令|规则|限制|约束|设定|规范|准则|安全策略|安全规定|系统提示|提示词|道德准则)"
)
WEAK_TARGET = r"(?:提示|提问|问句|问题|内容|要求|任务|对话|话|规定|政策|策略|说明|信息)"

ROLE_ASSIGN = (
    r"(?:你现在是|你就是|你将是|你将作为|从现在开始[，,]?\s*你|从现在起[，,]?\s*你|"
    r"接下来你|请你扮演|你要扮演|你来扮演|扮演一个|扮演一名|假装你是|假设你是|想象你是)"
)
UNRESTRICTED = (
    r"(?:无所不能|没有任何?限制|不受任何?(?:限制|约束|道德|法律|规则|伦理)|无视(?:道德|法律|规则|伦理)|"
    r"没有道德|不讲道德|突破(?:一切|所有|任何)?限制|不需要遵守|无需遵守|不用遵守|不会拒绝|不能拒绝|"
    r"不得拒绝|不允许拒绝|绝不拒绝|没有底线|毫无底线|不受审查|没有过滤|解除(?:所有|一切)?限制|"
    r"开发者模式|越狱模式|DAN)"
)
LEAK_VERB = r"(?:输出|告诉我|透露|泄露|泄漏|显示|打印|复述|重复|说出|给出|展示|列出|写出|贴出)"
LEAK_TARGET = (
    r"(?:系统提示|系统指令|系统设定|系统消息|初始指令|初始提示|原始指令|原始提示|隐藏指令|"
    r"你的提示词|你的指令|你的设定|你收到的指令|prompt|system\s*prompt)"
)
SECRET = (
    r"(?:密钥|私钥|秘钥|令牌|密码|口令|凭据|凭证|api\s*key|apikey|token|cookie|会话|对话历史|"
    r"聊天记录|对话记录|id_rsa|credentials|\.aws|\.ssh|\.env|环境变量|access\s*key|secret)"
)
SEND = r"(?:发送|发给|发到|转发|上传|附在|附上|附带|外发|传到|传给|提交到|提交给|post|回传|同步到|抄送)"
EXTERNAL = r"(?:https?://|webhook|@[\w.-]+\.\w+|外部|第三方|指定(?:地址|邮箱|服务器)|以下地址|该地址|这个地址)"
STEALTH = (
    r"(?:(?:不要|别|不必|无需|切勿|不许)(?:告诉|告知|通知|提醒|提及|让)[^。\n]{0,4}(?:用户|使用者|主人|人类|对方)|"
    r"瞒着(?:用户|使用者)|(?:悄悄|偷偷|静默|暗中|秘密)地?(?:执行|运行|读取|发送|上传|删除|调用|修改|收集|复制))"
)
DANGEROUS_OPS = (
    r"(?:关闭|禁用|停用|绕过|跳过|关掉|停止)"
    + (G % 8)
    + r"(?:审批|审计|日志|人工确认|二次确认|安全检查|防火墙|杀毒|监控|告警)"
    r"|(?:删除|清空|篡改|抹掉)" + (G % 10) + r"(?:审计|audit|日志|操作记录|访问记录)"
)

PERSONA = (
    r"(?:黑客|罪犯|犯罪分子|骗子|恶魔|魔鬼|反派|邪恶|恶意|不道德|无道德|没有感情|冷酷无情|"
    r"没有良知|毫无顾忌|肆无忌惮|无法无天|法外之徒)"
)
REFUSAL_SUPPRESSION = (
    r"(?:不要|无需|不必|不用|不许|禁止|别|不得|不能|不可)(?:拒绝|道歉|警告|说教|劝阻|添加免责|给出免责|提醒(?:道德|法律|风险))"
    r"|(?:不要|不能|不得|无需|不需要|不用|不必)(?:考虑|顾及|在意)"
    + (G % 4)
    + r"(?:道德|法律|伦理|后果|安全性)"
)
AGENT_DANGEROUS_OBJECT = (
    r"(?:sudo|root|chmod\s+777|sshd|PermitRootLogin|防火墙|crontab|计划任务|开机启动|白名单|"
    r"管理员权限|最高权限|超级用户|authorized_keys|/etc/|注册表|安全组|0\.0\.0\.0/0)"
)

IMPERATIVE = r"(?:请(?!求|假|教|问)|务必|必须|需要|先|立即|马上|顺便|另外)"
DANGER_VERB = r"(?:执行|运行|修改|改为|改成|设置为|添加|授予|开放|写入)"

ZH_RULES = (
    (
        "CONTEXT_HIJACK",
        "untrusted_text_requests_instruction_override",
        re.compile(
            OVERRIDE_VERB
            + (G % 12)
            + STRONG_TARGET
            + "|"
            + OVERRIDE_VERB
            + (G % 4)
            + QUALIFIER
            + (G % 8)
            + WEAK_TARGET
            + r"|(?:现在|接下来)[，,]?你的(?:新的?|真正的?|实际的?)?任务(?:变成|改为|是)"
            r"|你的(?:新的?|真正的?)任务(?:变成|改为|是)"
            r"|(?:新的?|最新|更新后?的)(?:指令|指示|任务)[:：]"
            r"|(?:直接|只需|仅需|只要|但现在请?|而是)(?:输出|回答|回复|复述|说出?)\s*[:：“\"「]"
            r"|(?:不要|别|不用)(?:管|理会|回答)" + (G % 4) + r"(?:上述|上面|以上|之前|前面)"
        ),
    ),
    (
        "CONTEXT_HIJACK",
        "untrusted_text_assigns_unrestricted_role",
        re.compile(
            ROLE_ASSIGN
            + r"[^\n]{0,200}?"
            + UNRESTRICTED
            + "|"
            + UNRESTRICTED
            + r"[^\n]{0,60}?"
            + ROLE_ASSIGN
            + "|"
            + ROLE_ASSIGN
            + r"[^。\n]{0,40}?"
            + PERSONA
            + "|"
            + REFUSAL_SUPPRESSION
            + r"|(?:进入|开启|启用|切换到)(?:开发者|越狱|无限制|上帝|管理员)模式",
            re.I,
        ),
    ),
    (
        "CONTEXT_HIJACK",
        "untrusted_text_requests_prompt_or_secret_disclosure",
        re.compile(LEAK_VERB + (G % 15) + LEAK_TARGET, re.I),
    ),
    (
        "TOOL_POISONING",
        "untrusted_text_directs_sensitive_exfiltration",
        re.compile(
            SEND
            + r"[^\n]{0,40}?"
            + SECRET
            + r"[^\n]{0,40}?"
            + EXTERNAL
            + "|"
            + SECRET
            + r"[^\n]{0,40}?"
            + SEND
            + r"[^\n]{0,40}?"
            + EXTERNAL
            + "|"
            + SEND
            + r"[^\n]{0,30}?"
            + EXTERNAL
            + r"[^\n]{0,30}?"
            + SECRET,
            re.I,
        ),
    ),
    (
        "TOOL_POISONING",
        "untrusted_text_directs_covert_action",
        re.compile(
            STEALTH
            + r"|(?:调用|使用|列出|加载)(?:此|该|本|这个)工具(?:时|前|之前|后)"
            + (G % 6)
            + r"(?:必须|务必|请先|先|同时|一定要|还要)"
            r"|(?:^|['‘“「:：\[【(（<])\s*(?:系统|管理员|开发者)(?:消息|通知|指令|提示)?\s*[:：\]】)）>]"
            r"|<\s*/?\s*重要\s*>"
            r"|(?:执行|运行)\s*(?:curl|wget)[^\n|]{0,120}\|\s*(?:ba|z)?sh",
            re.I | re.M,
        ),
    ),
    (
        "TOOL_POISONING",
        "untrusted_text_directs_agent_action",
        re.compile(
            IMPERATIVE
            + (G % 6)
            + "(?:"
            + DANGEROUS_OPS
            + ")"
            + r"|(?:绕过|跳过)(?:所有|全部|一切)?的?(?:安全检查|审批|确认步骤|人工确认|二次确认)"
            + "|"
            + IMPERATIVE
            + (G % 20)
            + DANGER_VERB
            + (G % 30)
            + AGENT_DANGEROUS_OBJECT
            + "|"
            + IMPERATIVE
            + (G % 8)
            + AGENT_DANGEROUS_OBJECT
            + (G % 30)
            + DANGER_VERB
            + r"|(?:下载|拉取)"
            + (G % 30)
            + r"(?:并|然后|后)(?:执行|运行|安装)",
            re.I,
        ),
    ),
)


def scan_zh(view: str) -> tuple[str, str] | None:
    if not re.search(r"[\u3400-\u9fff]", view):
        return None
    folded = fold_zh(view)
    for family, reason, pattern in ZH_RULES:
        if pattern.search(folded):
            return family, reason
    return None
