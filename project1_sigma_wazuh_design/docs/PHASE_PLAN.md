# Implementation Roadmap — Project I

Nguyên tắc: mỗi phase có mục tiêu, đầu việc nhỏ, kiểm thử, tiêu chí nghiệm thu và báo cáo Markdown. Không bắt đầu phase tiếp theo khi phase hiện tại còn lỗi blocker hoặc kết quả chưa được ghi nhận.

## Phase 0 — Requirements, architecture and dataset baseline
**Mục tiêu:** thống nhất phạm vi, kiến trúc và dữ liệu đầu vào.

Đầu việc:
1. Review SRS/SAD và ghi các quyết định còn mở.
2. Tải SigmaHQ theo quy trình trong `DATASET_GUIDE.md`.
3. Ghi commit SHA, file count, checksum manifest.
4. Kiểm tra tất cả file có tồn tại, YAML/pySigma parsing, metadata và ID trùng.
5. Tạo inventory feature: field, modifier, condition, logsource.
6. Tạo curated smoke/regression set có chủ đích; ghi lý do chọn từng rule.
7. Khóa các phiên bản công cụ và dependencies.

Tests/evidence:
- Không có đường dẫn manifest nào bị thiếu.
- File có lỗi được liệt kê riêng; không âm thầm loại.
- Báo cáo phân loại được rule hợp lệ/không hợp lệ và feature coverage.
- Có thể tái tạo dataset từ commit đã ghi.

Deliverable: `reports/phase-0-dataset-and-design.md`.

## Phase 1 — Repository skeleton and development tooling
**Mục tiêu:** tạo nền tảng code sạch trước khi có logic conversion.

Đầu việc:
1. Tạo package `src/`, `tests/`, `config/`, `input/`, `output/`, `reports/`, `docs/`.
2. Thiết lập virtualenv, `requirements.txt` hoặc lock strategy, `.gitignore`.
3. Thiết lập pytest, logging và CLI skeleton.
4. Tạo config loading với validation; không hard-code absolute paths.
5. Viết README cài đặt/chạy/test.

Tests:
- Import package được.
- CLI `--help` chạy.
- Config hợp lệ được đọc; config sai trả lỗi rõ ràng.
- pytest chạy được trong môi trường sạch.

Deliverable: `reports/phase-1-foundation.md`.

## Phase 2 — Input loading and Sigma parsing
**Mục tiêu:** nạp rule và parse ổn định bằng pySigma.

Đầu việc:
1. Đọc một file và một thư mục theo thứ tự xác định.
2. Xử lý missing path, encoding, YAML/pySigma errors.
3. Trích xuất metadata và source provenance.
4. Tiếp tục batch khi một rule lỗi.
5. Sinh kết quả parse JSON có cấu trúc.

Tests:
- 3–5 smoke rules đơn giản.
- YAML lỗi, file rỗng, metadata optional, thư mục rỗng.
- Batch chứa cả rule tốt và lỗi.
- Không crash toàn batch.

Deliverable: `reports/phase-2-parser.md`.

## Phase 3 — Feature inventory and support analyzer
**Mục tiêu:** biết rõ rule nào hỗ trợ được trước khi sinh XML.

Đầu việc:
1. Trích xuất field, modifier, selection/filter và condition.
2. Phân loại feature hỗ trợ/chưa hỗ trợ.
3. Định nghĩa status và diagnostics code.
4. Tạo report coverage từ corpus.

Tests:
- Một test cho mỗi feature được công bố.
- Condition lồng nhau và feature chưa hỗ trợ phải bị đánh dấu.
- Không sinh đầu ra conversion cho case unsupported.

Deliverable: `reports/phase-3-support-analysis.md`.

## Phase 4 — Field mapping and condition conversion
**Mục tiêu:** chuyển đổi tập con an toàn sang IR hoặc cấu trúc trung gian tương đương.

Đầu việc:
1. Chốt mapping có căn cứ từ log/decoder.
2. Hỗ trợ lần lượt Image, CommandLine, ParentImage, OriginalFileName, User nếu dữ liệu Wazuh xác nhận.
3. Hỗ trợ modifier từng cái: endswith, startswith, contains, contains|all.
4. Hỗ trợ condition từng lớp: selection; all of selection_*; 1 of selection*; selection and not filter.
5. Từ chối semantics không thể bảo toàn.

Tests:
- Unit test mapping cho từng field/operator.
- Test AND/OR/NOT, danh sách giá trị, escape và trường hợp rỗng.
- Regression tests chống làm mất filter/condition.

Deliverable: `reports/phase-4-mapping.md`.

## Phase 5 — Wazuh XML generation and validation
**Mục tiêu:** sinh XML an toàn và kiểm tra được.

Đầu việc:
1. Tạo XML bằng XML library, không nối chuỗi thủ công.
2. Tạo allocator cho rule ID và phát hiện trùng.
3. Sinh description/group/mitre metadata chỉ khi mapping có căn cứ.
4. Validate XML well-formed và constraints.
5. Kiểm tra Wazuh rule loading trong lab bằng phương pháp phù hợp với phiên bản cài đặt.

Tests:
- Parse XML bằng parser.
- XML escaping.
- ID unique trong batch.
- Invalid/unsupported input không tạo XML giả thành công.
- Lưu log/evidence của Wazuh validation.

Deliverable: `reports/phase-5-xml-validation.md`.

## Phase 6 — Automated tests and evaluation
**Mục tiêu:** đánh giá hành vi phát hiện, không chỉ cú pháp.

Đầu việc:
1. Tạo positive/negative fixtures cho từng rule/feature được chọn.
2. Xác định fixture unit test khác với log integration thực.
3. Chạy regression suite.
4. Đo conversion coverage, unsupported rate và test pass rate.
5. Ghi hạn chế và các false-positive/false-negative đã quan sát.

Tests:
- Positive case đúng kỳ vọng.
- Negative case đúng kỳ vọng.
- Thiếu field, giá trị khác chữ hoa/thường, nhiều giá trị và logic filter.
- Báo cáo có số liệu khớp với test output.

Deliverable: `reports/phase-6-test-and-evaluation.md`.

## Phase 7 — Reporting and batch CLI
**Mục tiêu:** công cụ dùng được theo lô.

Đầu việc:
1. CLI input/output/config rõ ràng.
2. Xuất JSON theo từng rule và summary.
3. Hỗ trợ exit code phù hợp với batch result.
4. Đảm bảo output xác định và không ghi đè dữ liệu không chủ ý.
5. Chạy toàn bộ corpus và curated suite.

Tests:
- End-to-end CLI test.
- JSON schema/required fields.
- Summary count bằng tổng các record.
- Batch lỗi một phần vẫn tạo report.

Deliverable: `reports/phase-7-cli-reporting.md`.

## Phase 8 — Telegram ChatOps
**Mục tiêu:** gửi báo cáo sau khi conversion/report ổn định.

Đầu việc:
1. Đọc token/chat ID từ biến môi trường.
2. Gửi summary ngắn, không gửi secret.
3. Xử lý network/API failure riêng.
4. Có chế độ tắt Telegram khi test/local.
5. Tài liệu hóa cấu hình bot.

Tests:
- Mock API success/failure.
- Thiếu token có thông báo an toàn.
- Telegram failure không làm mất JSON report.
- Quét repository để tránh secret bị commit.

Deliverable: `reports/phase-8-telegram.md`.

## Phase 9 — Controlled lab integration and final evaluation
**Mục tiêu:** xác minh quy trình từ rule đến Wazuh theo cách có thể lặp lại.

Đầu việc:
1. Xác nhận log source/decoder/field names thực tế.
2. Deploy thủ công hoặc qua bước có xác nhận; không deploy unsupported/partial.
3. Chạy Wazuh validation, positive/negative scenarios.
4. Thu thập evidence, log, cấu hình và kết quả.
5. Chốt limitations, demo flow và báo cáo tổng kết.

Tests:
- Wazuh chấp nhận rule.
- Có bằng chứng alert cho positive case và không alert cho negative case theo kịch bản.
- Có rollback/cleanup được tài liệu hóa.
- Tổng kết không đánh đồng XML valid với detection correct.

Deliverable: `reports/phase-9-final-evaluation.md`.

## Mẫu báo cáo bắt buộc sau mỗi phase

Mỗi `reports/phase-N-*.md` phải có:
1. Mục tiêu và phạm vi phase.
2. Các thay đổi theo file/module.
3. Lệnh đã chạy và môi trường/phiên bản.
4. Test summary: passed/failed/skipped và kết quả cụ thể.
5. Bằng chứng hoặc đường dẫn log/artifact.
6. Lỗi đã sửa và lỗi còn tồn tại.
7. Quyết định kỹ thuật mới/điều chỉnh tài liệu.
8. Tiêu chí nghiệm thu: PASS/FAIL kèm lý do.
9. Rủi ro và việc cần làm tiếp theo.

Không cho phép báo cáo chỉ ghi “all tests passed” mà thiếu lệnh, số liệu hoặc evidence.
