# Software Architecture Document (SAD)
## Project I — Sigma-to-Wazuh Rule Converter

- Phiên bản: 0.1 (draft for review)
- Phong cách: modular monolith / Python package + CLI
- Trạng thái: thiết kế, chưa triển khai

## 1. Quyết định kiến trúc

- Một ứng dụng Python chạy cục bộ; không microservices.
- CLI là giao diện đầu tiên; không làm web UI trong MVP.
- pySigma dùng để parse/model/diễn giải Sigma, không giả định có backend Wazuh chính thức.
- Mapping và XML generation là logic do dự án sở hữu.
- Output/report là file; chưa cần database.
- Telegram là adapter tùy chọn, được bổ sung sau.
- Không tự động deploy theo mặc định.

## 2. Context và triển khai

```text
Ubuntu Host (development)
┌────────────────────────────────────────────────────────────┐
│ CLI / main                                                  │
│   ├── Input loader                                          │
│   ├── pySigma parser                                        │
│   ├── Support analyzer                                      │
│   ├── Field/condition mapper                                │
│   ├── Wazuh XML generator                                   │
│   ├── Validator                                             │
│   ├── Test runner / reporter                                │
│   └── Telegram notifier (later, optional)                   │
└────────────────────────────┬───────────────────────────────┘
                             │ manual/controlled lab integration
                             v
                  Wazuh VM: 192.168.56.40
                  Manager / Indexer / Dashboard

Ubuntu Host: 192.168.56.1
```

Sơ đồ này là deployment view tối giản. Chưa giả định Windows/Sysmon agent tồn tại. Kiểm thử rule Windows cần fixtures có schema phù hợp và/hoặc nguồn telemetry Windows thực tế. JSON fixture tự tạo có thể kiểm tra logic chương trình nhưng không thay thế được kiểm thử end-to-end trên Wazuh.

## 3. Pipeline xử lý

1. Discover inputs: resolve file paths; sort deterministically; reject missing paths.
2. Load source: đọc YAML UTF-8 và giữ raw content/hash.
3. Parse: tạo Sigma rule model bằng pySigma.
4. Analyze: liệt kê field, modifier, condition, logsource và các feature.
5. Map: chuyển model thành một biểu diễn trung gian riêng (IR) nếu điều đó giúp giữ logic rõ ràng.
6. Generate: sinh XML từ IR đã được hỗ trợ.
7. Validate: XML well-formed, ID uniqueness, required structure và rule constraints.
8. Test: unit/regression; lab validation ở phase sau.
9. Report: JSON + console; cập nhật trạng thái cho từng rule.
10. Notify: gửi summary Telegram nếu được bật và cấu hình hợp lệ.

Không nên buộc mọi rule đi đến bước generate. Unsupported phải dừng trước khi sinh rule không an toàn.

## 4. Module và trách nhiệm

| Module dự kiến | Trách nhiệm | Không chịu trách nhiệm |
|---|---|---|
| `main.py` | CLI, điều phối pipeline | Chứa logic chuyển đổi chi tiết |
| `input_loader.py` | Tìm/đọc file, kiểm tra đường dẫn, tạo input record | Parse semantics |
| `sigma_parser.py` | Parse bằng pySigma, chuẩn hóa lỗi parser | Sinh Wazuh XML |
| `support_analyzer.py` | Phân loại feature được hỗ trợ | Âm thầm sửa rule |
| `rule_mapper.py` | Map field/modifier/condition sang IR | Ghi file, gọi Telegram |
| `field_mapping.yaml` hoặc cấu hình tương đương | Khai báo mapping có tài liệu | Thay thế kiểm thử mapping |
| `wazuh_generator.py` | Sinh XML từ IR | Đoán field decoder |
| `validator.py` | XML syntax, ID uniqueness, structural constraints | Khẳng định detection đúng chỉ từ XML |
| `test_runner.py` | Chạy test/fixture được định nghĩa | Thay thế test Wazuh integration |
| `reporter.py` | JSON và console summary | Thay đổi kết quả conversion |
| `telegram_notifier.py` | Gửi summary qua Bot API | Giữ token trong source |
| `tests/` | Unit, regression, integration fixtures | Chứa secrets |

Có thể điều chỉnh module khi implementation bắt đầu, nhưng mọi thay đổi phải được ghi trong báo cáo phase.

## 5. Biểu diễn trung gian (IR)

Đề xuất IR tối thiểu trước khi sinh XML:
- `source`: relative path, source commit, SHA-256.
- `metadata`: title, id, description, status, level, tags, falsepositives.
- `logsource`: product/category/service/definition.
- `predicates`: các điều kiện field/operator/value.
- `condition`: cây logic AND/OR/NOT hoặc cấu trúc tương đương.
- `support`: supported features, unsupported features, reasons.
- `conversion_status`: SUCCESS/PARTIAL/FAILED/UNSUPPORTED.
- `diagnostics`: mã lỗi, thông báo, vị trí nếu có.

Không làm phẳng condition thành danh sách field-value nếu việc đó làm mất AND/OR/NOT. Nếu chưa có IR đủ để giữ semantics, nên hỗ trợ một tập con nhỏ hơn thay vì sinh XML gần đúng.

## 6. Trạng thái rule

- `SUCCESS`: conversion và các kiểm tra được định nghĩa cho phase đều qua.
- `PARTIAL`: chỉ dùng khi phần bị mất/khác biệt được ghi chính xác; không deploy mặc định.
- `UNSUPPORTED`: rule hợp lệ nhưng có feature chưa được hỗ trợ.
- `FAILED`: input lỗi hoặc pipeline gặp lỗi thực thi.

Nên có thêm các cờ độc lập như `xml_valid`, `wazuh_load_valid`, `positive_test_passed`, `negative_test_passed`, tránh gộp nhiều loại bằng chứng thành một status duy nhất.

## 7. Quy tắc sinh Wazuh XML

- ID được cấp bởi một allocator riêng, trong dải cấu hình, và kiểm tra trùng với cả batch lẫn lab.
- Không hard-code `if_sid`/`decoded_as` trước khi xác định loại log và decoder thực tế.
- Field path như `win.eventdata.image` hay `data.win.eventdata.image` phải được xác minh bằng log/decoder của môi trường đang dùng; không coi hai dạng là hoán đổi tùy ý.
- Escape XML bằng thư viện chuẩn; không nối chuỗi không an toàn.
- Giữ nội dung điều kiện đầy đủ; không bỏ filter hay modifier chưa hỗ trợ.
- XML well-formed không chứng minh Wazuh sẽ nạp rule hay phát hiện đúng.

## 8. Logging và reporting

Mỗi record kết quả nên gồm:
- `rule_path`, `rule_id`, `title`, `source_commit`, `sha256`.
- `status`, `diagnostics`, `unsupported_features`.
- `xml_path` nếu có đầu ra.
- `xml_valid`, `wazuh_load_valid`, test outcomes.
- phiên bản Python, pySigma, converter và thời điểm chạy.

Tóm tắt phải được tính từ record kết quả, không tự cộng số độc lập để tránh lệch số liệu.

## 9. Bảo mật và an toàn vận hành

- Telegram token đọc từ biến môi trường; `.env` nếu dùng phải được gitignore.
- Không log token hoặc nội dung bí mật.
- Không deploy `PARTIAL`, `FAILED`, `UNSUPPORTED`.
- Giai đoạn đầu chỉ ghi output ra thư mục dự án.
- Khi tích hợp lab, dùng bản sao cấu hình và có phương án rollback.
- Không tự khởi động lại Wazuh hoặc sửa cấu hình lab nếu chưa có thao tác triển khai được phê duyệt.

## 10. Các rủi ro kiến trúc

| Rủi ro | Giảm thiểu |
|---|---|
| Field Sigma không tương ứng trực tiếp với decoder Wazuh | Xác minh bằng log thực và cấu hình mapping theo log source |
| Logic Sigma bị mất khi chuyển đổi | IR có cây logic; unsupported nếu không bảo toàn được |
| ID Wazuh xung đột | Allocator + kiểm tra batch/lab |
| Dataset upstream thay đổi | Ghi commit SHA và checksum |
| pySigma API thay đổi | Pin version, test parser, ghi phiên bản |
| Test fixture không phản ánh Wazuh thực | Tách unit test và lab integration test |
| Telegram lỗi mạng | Notification là bước tùy chọn; không làm mất report |
| Cursor tạo code khó hiểu | Phase nhỏ, review diff, test bắt buộc và báo cáo Markdown |

## 11. Quyết định còn mở

1. Chọn commit/tag SigmaHQ cụ thể để đóng băng dataset đầu tiên.
2. Chọn phiên bản pySigma tương thích Python trong môi trường thực tế và pin dependency.
3. Xác minh cấu trúc log/decoder Wazuh trước khi khóa field mapping.
4. Chốt có cần IR riêng ngay MVP hay dùng model đơn giản nhưng vẫn bảo toàn logic.
5. Chốt phương pháp Wazuh integration test và nguồn log Windows/Sysmon.
6. Chốt số lượng rule trong curated regression suite; không mặc định rằng 100 rule là tối ưu.
