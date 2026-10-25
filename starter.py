#!/usr/bin/env python3
"""LAB 2 — GUARDRAIL VÀ VÁ LỖI CÓ KIỂM SOÁT
================================================================
Chủ đề: làm sao để AI Agent KHÔNG thể gây hại, kể cả khi nó bị lừa.

Sinh viên hoàn thiện các hàm có  ### TODO ###   rồi chạy:

    python check_lab2.py

KHÔNG sửa tên hàm và kiểu trả về.
"""
from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DATA = Path(__file__).parent / "data"


class SafetyViolation(Exception):
    """Ném ra khi một thao tác vi phạm ràng buộc an toàn."""


@dataclass
class PatchPlan:
    """Thứ DUY NHẤT mà LLM được phép trả về ở pha Patch."""
    recipe_id: str | None = None
    variables: dict = field(default_factory=dict)
    reason: str = ""


@dataclass
class ValidationResult:
    ok: bool
    messages: list = field(default_factory=list)


def load_recipes() -> dict:
    """Nạp toàn bộ recipe trong data/recipes/*.yaml — đã cho sẵn."""
    out = {}
    for p in sorted((DATA / "recipes").glob("*.yaml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        out[d["id"]] = d
    return out


# ==================================================================
# PHẦN 1 — Phát hiện tiêm lệnh (prompt injection)
# ==================================================================
# Kẻ tấn công có thể điều khiển nội dung mà SOC agent phải đọc: tiêu đề
# finding, HTTP header, tên tệp, nội dung trang web... Nếu agent làm theo
# mệnh lệnh giấu trong đó, nó đã bị chiếm quyền.

INJECTION_PATTERNS: list[str] = [
    # Đã cho sẵn 2 mẫu làm ví dụ. Sinh viên bổ sung thêm.
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"bỏ\s*qua\s+(các\s+)?(hướng\s*dẫn|chỉ\s*thị)\s*(trước|trên)?",
    ### TODO 1 ### — bổ sung mẫu cho các nhóm sau (xem data/injection_cases.yaml):
    #   - vượt cổng phê duyệt: "requires_human_approval=false", "skip the approval",
    #     "bỏ qua phê duyệt", "approved=true"
    #   - thao túng điểm: "mark all ... P4", "đánh dấu tất cả ... P4",
    #     "downgrade severity", "risk_priority_score="
    #   - giả mạo thẻ hệ thống: "<system>", "[INST]", "SYSTEM OVERRIDE"
    #   - dụ sinh mã khai thác: "reverse shell", "msfconsole",
    #     "viết/write ... payload|exploit"
    #   - rò rỉ dữ liệu: "system prompt", "API_KEY", ".env"
]


def detect_injection(text: str) -> list[str]:
    """Trả về danh sách mẫu (pattern) khớp với text. Rỗng = sạch.

    Yêu cầu:
      - so khớp KHÔNG phân biệt hoa thường
      - text rỗng/None → trả []
      - CHUẨN HOÁ trước khi so khớp để bắt biến thể né tránh:
          "README_ignore_previous_instructions.txt"  (dấu _ thay khoảng trắng)
          "I-g-n-o-r-e a-l-l ..."                    (chèn gạch nối)
        Gợi ý: cần HAI biến thể chuẩn hoá, so khớp trên cả ba bản (gốc + 2 biến thể):
          (a) thay [_.-] bằng KHOẢNG TRẮNG  → bắt "README_ignore_previous_..."
          (b) XOÁ dấu nằm giữa hai chữ cái  → bắt "I-g-n-o-r-e a-l-l ..."
              regex gợi ý: r"(?<=\w)[-_.](?=\w)"
    """
    ### TODO 2 ### — viết code của bạn ở đây
    return []


def wrap_untrusted(label: str, payload: str) -> str:
    """Bọc dữ liệu không tin cậy trước khi đưa vào prompt.

    Trả về chuỗi có ĐỦ 3 yếu tố:
      1. thẻ mở <untrusted_data source="{label}"> và thẻ đóng </untrusted_data>
      2. một câu cảnh báo cho mô hình rằng đây là DỮ LIỆU, KHÔNG phải chỉ thị
      3. nguyên văn payload ở giữa

    Vì sao cần? Đây là lớp phòng thủ "tách dữ liệu khỏi mệnh lệnh".
    """
    ### TODO 3 ### — viết code của bạn ở đây
    return ""


# ==================================================================
# PHẦN 2 — Cưỡng chế phạm vi
# ==================================================================
def check_scope(target: str, allowed: list[str]) -> None:
    """Cho qua nếu target nằm trong phạm vi; ngược lại NÉM SafetyViolation.

    Quy tắc:
      - so khớp chính xác, HOẶC khớp phần host (bỏ cổng): "localhost:3000"
        được chấp nhận nếu allowed có "localhost"
      - nếu mục allowed có dạng CIDR ("192.168.56.0/24") thì kiểm tra target
        có phải IP thuộc dải đó không (gợi ý: module ipaddress)
      - target rỗng → cũng ném SafetyViolation
    """
    ### TODO 4 ### — viết code của bạn ở đây


# ==================================================================
# PHẦN 3 — Recipe Engine: xác thực kế hoạch vá
# ==================================================================
# Nguyên tắc vàng: LLM KHÔNG được viết script. Nó chỉ CHỌN recipe đã được
# con người duyệt trước và ĐIỀN biến. Code kiểm tra lại từng biến.

def validate_plan(plan: PatchPlan, recipes: dict) -> ValidationResult:
    """Kiểm tra kế hoạch vá do LLM đề xuất.

    PHẢI từ chối (ok=False) trong các trường hợp:
      a) recipe_id là None hoặc KHÔNG có trong thư viện đã duyệt
      b) thiếu biến bắt buộc (required: true và không có default)
      c) giá trị biến KHÔNG khớp allow_pattern
         → dùng re.fullmatch, KHÔNG dùng re.match/search (vì sao? hãy suy nghĩ)
      d) có biến LẠ không khai báo trong recipe

    Nếu biến vắng mặt nhưng recipe có 'default' → điền giá trị mặc định và
    vẫn coi là hợp lệ.

    messages: ghi rõ lý do từng biến (để sinh viên/giảng viên đọc được).
    """
    msgs: list[str] = []
    if not plan.recipe_id or plan.recipe_id not in recipes:
        msgs.append(f"Recipe không được phê duyệt: {plan.recipe_id}")
        return ValidationResult(ok=False, messages=msgs)

    definitions = recipes[plan.recipe_id].get("variables", {})
    valid = True

    for name in plan.variables:
        if name not in definitions:
            msgs.append(f"Biến lạ không được khai báo: {name}")
            valid = False

    for name, spec in definitions.items():
        if name not in plan.variables:
            if "default" in spec:
                plan.variables[name] = spec["default"]
            elif spec.get("required", False):
                msgs.append(f"Thiếu biến bắt buộc: {name}")
                valid = False
                continue
            else:
                continue

        value = plan.variables[name]
        pattern = spec.get("allow_pattern")
        if not isinstance(value, str) or (pattern is not None and re.fullmatch(pattern, value) is None):
            msgs.append(f"Giá trị biến {name} không khớp allow_pattern: {value!r}")
            valid = False

    return ValidationResult(ok=valid, messages=msgs)


def render_argv(step: dict, variables: dict) -> list[str]:
    """Thay {{bien}} trong step["argv"] bằng giá trị thật, trả về DANH SÁCH.

    Yêu cầu:
      - chỉ thay placeholder có tên nằm trong variables
      - placeholder KHÔNG phải biến của ta thì giữ nguyên
        (ví dụ "{{.Server.Version}}" của Docker — có dấu chấm, không phải biến)
      - kết quả là list[str], KHÔNG BAO GIỜ nối thành một chuỗi shell

    Vì sao trả list? Vì subprocess.run(argv, shell=False) sẽ coi mọi ký tự
    trong từng phần tử là DỮ LIỆU, không phải cú pháp shell.
    """
    pattern = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
    return [
        pattern.sub(lambda match: str(variables.get(match.group(1), match.group(0))), arg)
        for arg in step["argv"]
    ]


def execute_step(step: dict, dry_run: bool = True) -> tuple[bool, str]:
    """Thực thi một bước. Trả về (thành_công, mô_tả).

    Yêu cầu:
      - dry_run=True (MẶC ĐỊNH): KHÔNG chạy gì, chỉ trả (True, "[DRY-RUN] <lệnh>")
      - dry_run=False: chạy bằng subprocess.run(argv, shell=False,
        capture_output=True, text=True, timeout=30)
        · returncode == 0 → (True, stdout)
        · khác 0          → (False, stderr hoặc "rc=<mã>")
        · FileNotFoundError → (False, "Không tìm thấy lệnh: <argv[0]>")

      BẮT BUỘC: shell=False. Đây là điều kiện để chống chèn lệnh.
    """
    argv = step["argv"]
    if dry_run:
        return True, f"[DRY-RUN] {' '.join(argv)}"

    # Windows provides echo as a shell built-in, not an executable. Run an
    # equivalent process so shell=False remains safe and stdout is captured.
    command = argv
    if sys.platform == "win32" and argv[0].lower() == "echo":
        command = [sys.executable, "-c", "import sys; print(' '.join(sys.argv[1:]))", *argv[1:]]

    try:
        result = subprocess.run(
            command, shell=False, capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        return False, f"Không tìm thấy lệnh: {argv[0]}"

    if result.returncode == 0:
        return True, result.stdout
    return False, result.stderr or f"rc={result.returncode}"


# ==================================================================
# PHẦN 4 — Cổng phê duyệt của con người
# ==================================================================
class ApprovalGate:
    """Ghi nhận và cưỡng chế quyết định phê duyệt.

    Ý tưởng: cổng phê duyệt phải nằm ở TẦNG LOGIC, không phải ở giao diện.
    Dù ai gọi thẳng hàm apply_patch() cũng phải bị chặn nếu chưa duyệt.
    """

    def __init__(self) -> None:
        self.audit: list[dict] = []

    def record(self, gate: str, decision: str, detail: str = "") -> None:
        """Ghi một quyết định vào audit trail.

        decision chỉ nhận "approve" hoặc "reject"; giá trị khác → ValueError.
        Mỗi bản ghi là dict có đủ khoá: gate, decision, detail.
        """
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        self.audit.append({"gate": gate, "decision": decision, "detail": detail})

    def is_approved(self, gate: str) -> bool:
        """True chỉ khi cổng này có ÍT NHẤT một bản ghi decision == 'approve'."""
        return any(
            entry["gate"] == gate and entry["decision"] == "approve"
            for entry in self.audit
        )


def apply_patch(plan: PatchPlan, recipes: dict, gate: ApprovalGate,
                dry_run: bool = True) -> dict:
    """Áp dụng bản vá — có đủ các chốt an toàn.

    Trình tự BẮT BUỘC:
      1. validate_plan(); nếu không hợp lệ → trả {"status": "blocked", ...}
         (KHÔNG được chạy gì cả)
      2. kiểm tra gate.is_approved("gate2_patch"); nếu chưa duyệt →
         trả {"status": "rejected", ...}   (KHÔNG được chạy gì cả)
      3. chạy lần lượt pre_checks → apply → regression_tests
      4. nếu CÓ BẤT KỲ regression test nào thất bại → chạy các bước rollback
         và trả {"status": "rolled_back", ...}
      5. tất cả đạt → {"status": "closed", ...}

    Dict trả về gồm các khoá: status, recipe_id, steps (list mô tả),
    rollback_done (bool).
    """
    result = {
        "status": "blocked",
        "recipe_id": plan.recipe_id,
        "steps": [],
        "rollback_done": False,
    }
    validation = validate_plan(plan, recipes)
    if not validation.ok:
        result["steps"].extend(validation.messages)
        return result

    if not gate.is_approved("gate2_patch"):
        result["status"] = "rejected"
        return result

    recipe = recipes[plan.recipe_id]
    for phase in ("pre_checks", "apply", "regression_tests"):
        for step in recipe.get(phase, []):
            rendered = {**step, "argv": render_argv(step, plan.variables)}
            ok, description = execute_step(rendered, dry_run=dry_run)
            result["steps"].append(f"{step.get('name', phase)}: {description}")
            if phase == "regression_tests" and not ok:
                for rollback_step in recipe.get("rollback", []):
                    rendered = {**rollback_step, "argv": render_argv(rollback_step, plan.variables)}
                    _, description = execute_step(rendered, dry_run=dry_run)
                    result["steps"].append(f"{rollback_step.get('name', 'rollback')}: {description}")
                result["rollback_done"] = True
                result["status"] = "rolled_back"
                return result

    result["status"] = "closed"
    return result


# ==================================================================
# CHẠY THỬ
# ==================================================================
def main() -> None:
    recipes = load_recipes()
    print(f"Thư viện recipe đã duyệt: {list(recipes)}\n")

    # Kịch bản 1: LLM đề xuất hợp lệ
    good = PatchPlan(recipe_id="docker_compose_update_image",
                     variables={"service_name": "web",
                                "new_image_tag": "vulnerable-demo:1.1-patched"})
    gate = ApprovalGate()
    print("— Chưa phê duyệt:", apply_patch(good, recipes, gate).get("status"))
    gate.record("gate2_patch", "approve", "GV duyệt trong lab")
    print("— Sau phê duyệt :", apply_patch(good, recipes, gate).get("status"))

    # Kịch bản 2: LLM bị chiếm quyền, trả biến độc hại
    evil = PatchPlan(recipe_id="docker_compose_update_image",
                     variables={"service_name": "web",
                                "new_image_tag": "demo:1.1; rm -rf / #"})
    r = apply_patch(evil, recipes, gate)
    print("— Biến độc hại  :", r.get("status"), "(phải là 'blocked')")


if __name__ == "__main__":
    main()
