# Phân công Lab 2 — Guardrail và vá lỗi có kiểm soát

**Thời gian dự kiến:** 2–3 ngày  
**Mục tiêu:** Hoàn thiện 10 vị trí `TODO` trong `starter.py`, kiểm tra bằng `check_lab2.py` (tổng 23 điểm), và nộp `starter.py` cùng báo cáo ngắn. Mục 9 của đề là phần mở rộng, không bắt buộc.

## Bài lab này làm gì?

Giả lập một SOC agent được đề xuất bản vá nhưng phải bị mã nguồn kiểm soát. Dữ liệu quét có thể chứa prompt injection; mục tiêu thao tác phải nằm trong lab; agent chỉ được chọn recipe đã duyệt và điền biến hợp lệ. Trước khi vá phải kiểm tra kế hoạch rồi kiểm tra phê duyệt. Nếu kiểm thử sau vá thất bại thì quay lui.

## Việc chung trước khi bắt đầu

- [ ] Đọc mục 1, 2 và 7–8 của đề; xem `starter.py`, `data/injection_cases.yaml` và hai recipe trong `data/recipes/`.
- [ ] Trong thư mục `lab2`, cài PyYAML bằng `pip install pyyaml`, rồi chạy `python check_lab2.py` để xem điểm ban đầu.
- [ ] Mỗi người chỉ sửa các `TODO` mình phụ trách trong `starter.py` để tránh ghi đè phần của nhau. Không sửa `check_lab2.py` hay dữ liệu kiểm thử khi làm bài chính.
- [ ] Giữ `dry_run=True` khi chạy thử luồng vá bằng `starter.py`. Chỉ chạy thật các lệnh trên môi trường lab đã chuẩn bị.

## Huyền — Prompt injection và phạm vi hoạt động

Phụ trách **TODO 1–4**, tương ứng **Phần 1 và 2: 10,5/23 điểm**.

- [ ] **TODO 1 — `INJECTION_PATTERNS`:** thêm mẫu đủ các nhóm tấn công trong `injection_cases.yaml`: ghi đè chỉ thị, bỏ qua phê duyệt, thao túng điểm, giả mạo thẻ hệ thống, dụ tạo mã khai thác và rò rỉ dữ liệu. Giữ mẫu đủ hẹp để không bắt nhầm nội dung lành tính.
- [ ] **TODO 2 — `detect_injection`:** trả `[]` cho chuỗi rỗng/`None`; so khớp không phân biệt hoa thường; thử cả bản gốc, bản thay `_`, `.` và `-` bằng khoảng trắng, và bản xoá dấu chèn giữa các chữ cái.
- [ ] **TODO 3 — `wrap_untrusted`:** bọc nguyên văn payload trong `<untrusted_data source="...">...</untrusted_data>` và thêm câu cảnh báo đây là dữ liệu, không phải chỉ thị.
- [ ] **TODO 4 — `check_scope`:** cho qua mục tiêu khớp chính xác, host hợp lệ kèm cổng, hoặc IP thuộc CIDR cho phép; ném `SafetyViolation` với mục tiêu ngoài phạm vi hay rỗng.
- [ ] Chạy `python check_lab2.py` sau từng phần; nhắm đủ điểm các mục **1.1–2.2**. Riêng bộ 28 ca: bắt ít nhất 21/22 ca tấn công để đạt block rate ≥95%, đồng thời không bắt nhầm 6 ca lành tính.
- [ ] Ghi lại một mẫu regex đã phải thu hẹp vì báo nhầm để dùng cho câu 3 báo cáo. Phụ trách bản nháp câu **2 và 3** ở mục 8 của đề.

## Thành — Recipe Engine, phê duyệt và rollback

Phụ trách **TODO 5–10**, tương ứng **Phần 3 và 4: 12,5/23 điểm**.

- [ ] **TODO 5 — `validate_plan`:** từ chối recipe không có trong thư viện, thiếu biến bắt buộc, biến lạ và giá trị sai `allow_pattern`; điền `default` khi có; dùng `re.fullmatch` để kiểm tra toàn bộ giá trị.
- [ ] **TODO 6 — `render_argv`:** chỉ thay placeholder của biến đã khai báo; trả về `list[str]`; giữ nguyên placeholder Docker `{{.Server.Version}}`.
- [ ] **TODO 7 — `execute_step`:** mặc định dry run và không thực thi lệnh; khi chạy thật dùng `subprocess.run(argv, shell=False, ...)`, xử lý mã lỗi và trường hợp không tìm thấy lệnh.
- [ ] **TODO 8–9 — `ApprovalGate`:** `record` chỉ chấp nhận `approve`/`reject`, ghi đủ thông tin vào audit; `is_approved` chỉ kiểm tra phê duyệt của đúng gate.
- [ ] **TODO 10 — `apply_patch`:** kiểm tra `validate_plan` **trước** phê duyệt; chưa duyệt trả `rejected`, kế hoạch sai trả `blocked`; chạy `pre_checks → apply → regression_tests`; test thất bại thì rollback và trả `rolled_back`, thành công trả `closed`.
- [ ] Chạy `python check_lab2.py` sau từng phần; nhắm đủ điểm các mục **3.1–4.5**. Phụ trách bản nháp câu **1 và 4** ở mục 8 của đề.

## Lịch 2–3 ngày

| Thời điểm | Huyền | Thành | Mốc chung |
| --- | --- | --- | --- |
| Ngày 1 | Đọc 28 ca, làm TODO 1–3, đo block rate và false positive | Đọc recipe, làm TODO 5–7, kiểm tra biến độc hại và dry run | Chạy tự chấm; chia sẻ lỗi hoặc điểm còn thiếu |
| Ngày 2 | Làm TODO 4, sửa regex để đạt chỉ số, viết nháp câu 2–3 | Làm TODO 8–10, thử đủ các trạng thái, viết nháp câu 1 và 4 | Ghép `starter.py`, chạy toàn bộ checker và `starter.py`; hoàn thiện báo cáo |
| Ngày 3 nếu cần | Rà ca báo nhầm/bỏ sót | Rà luồng phê duyệt/rollback | Sửa lỗi còn lại, kiểm tra tệp nộp |

## Checklist trước khi nộp

- [ ] `python check_lab2.py` đạt mức điểm nhóm đặt ra, mục tiêu **23/23**. Ghi lại block rate và false positive rate thực tế từ lần chạy cuối.
- [ ] `python starter.py` cho ba trạng thái mẫu: chưa duyệt `rejected`, đã duyệt `closed`, biến độc hại `blocked`.
- [ ] Báo cáo ngắn trả lời đủ **4 câu ở mục 8**: `re.fullmatch` so với `re.match`; an toàn khi lớp phát hiện injection bị vượt; hai chỉ số phát hiện và một lần thu hẹp regex; lý do phê duyệt phải nằm trong `apply_patch`.
- [ ] Nộp `starter.py` đã hoàn thiện và báo cáo ngắn theo đề. Mục 9 chỉ làm nếu còn thời gian.

> `check_lab2.py` có ca gọi `execute_step(..., dry_run=False)` và ca thử rollback. Đọc các lệnh trong recipe, chạy ở môi trường lab và giữ `dry_run=True` cho các lần tự thử thông thường.
