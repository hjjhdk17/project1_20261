# Software Requirements Specification (SRS)
## Project I — Sigma-to-Wazuh Rule Conversion and Testing Prototype

- Phiên bản: 0.1 (draft for review)
- Trạng thái: Thiết kế, chưa triển khai
- Loại dự án: Prototype học thuật

## 1. Mục đích

Đặc tả yêu cầu cho một công cụ Python có khả năng đọc Sigma YAML, phân tích bằng pySigma, chuyển đổi một tập con được công bố rõ ràng sang Wazuh XML, xác thực đầu ra, ghi báo cáo và về sau gửi báo cáo qua Telegram.

## 2. Bối cảnh và vấn đề

Sigma là định dạng quy tắc phát hiện độc lập với nền tảng. Wazuh sử dụng rule XML, decoder và trường dữ liệu riêng. Chuyển đổi cú pháp không đảm bảo bảo toàn ngữ nghĩa; vì vậy công cụ phải thể hiện rõ mức độ hỗ trợ, từ chối trường hợp không thể chuyển đổi an toàn và kiểm thử hành vi đầu ra.

## 3. Mục tiêu

1. Đọc và phân tích các rule thuộc `rules/windows/process_creation/` của SigmaHQ.
2. Xây dựng bộ chuyển đổi có phạm vi hỗ trợ rõ ràng, có thể mở rộng.
3. Không tạo đầu ra như thể thành công khi phát hiện logic chưa được bảo toàn.
4. Kiểm tra cấu trúc XML và hỗ trợ kiểm thử bằng positive/negative fixtures.
5. Tạo báo cáo máy đọc được và bản tóm tắt console.
6. Tích hợp Telegram sau khi lõi chuyển đổi ổn định.

## 4. Ngoài phạm vi MVP

- Hỗ trợ toàn bộ Sigma specification hoặc mọi rule SigmaHQ.
- Tự động triển khai không có kiểm soát vào môi trường sản xuất.
- AI agent tự quyết định logic hoặc tự phê duyệt rule.
- Web UI, database server, Docker orchestration, microservices.
- Cam kết phát hiện tương đương 100% giữa Sigma và Wazuh.
- Tạo telemetry Windows/Sysmon hoàn chỉnh chỉ bằng Wazuh Manager.

## 5. Người dùng và môi trường vận hành

- Người dùng chính: sinh viên/người nghiên cứu vận hành CLI.
- Nền tảng phát triển: Ubuntu Linux.
- Runtime: Python 3.11+ theo yêu cầu dự án; phải xác minh tương thích dependency trước khi khóa phiên bản.
- SIEM kiểm chứng: Wazuh lab.
- Nguồn dữ liệu: SigmaHQ Git repository và file YAML cục bộ.

## 6. Yêu cầu chức năng

### FR-01 — Nhập rule
Hệ thống MUST nhận một file, một thư mục rule hoặc một danh sách file xác định. Không được dựa vào tên file tự suy đoán rằng file tồn tại.

### FR-02 — Theo dõi nguồn
Với mỗi rule, ghi lại đường dẫn tương đối, commit SHA của repository, tên file và SHA-256 của nội dung. Bộ dữ liệu phải tái tạo được.

### FR-03 — Parse Sigma
Sử dụng pySigma làm parser/model Sigma. Lỗi parse của một rule không được làm dừng toàn bộ batch.

### FR-04 — Trích xuất metadata
Trích xuất metadata có sẵn như title, id, description, status, level, logsource, detection/condition, tags và falsepositives. Trường optional bị thiếu phải được biểu diễn là absent, không tự tạo dữ liệu.

### FR-05 — Phân tích khả năng hỗ trợ
Trước khi sinh XML, phân loại cấu trúc rule và các feature được sử dụng. Tối thiểu phân biệt:
- `SUCCESS`: chuyển đổi, validation và các kiểm tra được cấu hình đều qua.
- `PARTIAL`: chỉ khi đã định nghĩa chính xác phần nào được bảo toàn và phần nào không; mặc định không triển khai.
- `UNSUPPORTED`: cú pháp/feature ngoài phạm vi được công bố.
- `FAILED`: đầu vào lỗi hoặc lỗi xử lý ngoài trường hợp unsupported.
Các nhãn không được dùng thay thế lẫn nhau.

### FR-06 — Ánh xạ field
Field mapping phải được khai báo trong cấu hình hoặc module riêng và có tài liệu giải thích. Không được giả định field Wazuh tồn tại trong mọi decoder/log source.

### FR-07 — Chuyển đổi detection
Chuyển đổi các điều kiện chỉ khi logic tương đương có thể biểu diễn được. Nếu không chứng minh được mapping an toàn, phải từ chối thay vì bỏ qua điều kiện/filter.

### FR-08 — Sinh XML
Sinh Wazuh XML well-formed, escape giá trị đúng cách, giữ quan hệ logic và metadata phù hợp. Rule ID phải duy nhất trong output và không xung đột với rule hiện có trong lab.

### FR-09 — Validation
Kiểm tra XML well-formed và cấu trúc theo schema/constraints mà công cụ hỗ trợ. Khi có lab integration, xác minh Wazuh có chấp nhận rule bằng công cụ kiểm tra chính thức của phiên bản đang dùng. XML parse được không đồng nghĩa Wazuh load được.

### FR-10 — Báo cáo
Xuất JSON theo từng rule và summary console, gồm số lượng SUCCESS/PARTIAL/FAILED/UNSUPPORTED, lỗi, feature chưa hỗ trợ, nguồn, thời gian chạy và phiên bản công cụ.

### FR-11 — Batch isolation
Một rule lỗi không được làm mất kết quả của các rule khác. Lỗi phải có context đủ để điều tra.

### FR-12 — Kiểm thử tự động
Có unit tests cho parser, mapper, generator và validator; có fixtures positive/negative cho các feature được hỗ trợ. Tất cả feature được thêm mới phải có regression test.

### FR-13 — Telegram (phase sau)
Gửi summary và lỗi quan trọng qua Telegram Bot API. Token phải đọc từ biến môi trường hoặc cơ chế secret bên ngoài; không được commit secret.

### FR-14 — Triển khai an toàn
MVP mặc định chỉ xuất XML và báo cáo. Triển khai vào Wazuh là bước riêng, có xác nhận và kiểm tra sau triển khai. Không tự động deploy rule `PARTIAL`, `FAILED` hoặc `UNSUPPORTED`.

## 7. Yêu cầu phi chức năng

- NFR-01 Readability: code Python dễ đọc, type hints, docstring ngắn, tên biến rõ ràng.
- NFR-02 Modularity: mỗi module có một trách nhiệm chính.
- NFR-03 Determinism: cùng input, cùng cấu hình và cùng phiên bản tạo kết quả tương đương.
- NFR-04 Observability: dùng `logging`; lỗi có file/rule và nguyên nhân.
- NFR-05 Resilience: batch tiếp tục sau lỗi riêng lẻ.
- NFR-06 Security: không chứa token, mật khẩu hoặc thông tin nhạy cảm trong source/report.
- NFR-07 Reproducibility: dependency có giới hạn phiên bản; dataset có commit và checksum.
- NFR-08 Testability: logic lõi không phụ thuộc bắt buộc vào kết nối Wazuh/Telegram.
- NFR-09 Portability: không hard-code đường dẫn tuyệt đối; hỗ trợ CLI.
- NFR-10 Academic transparency: mọi giới hạn và giả định phải được ghi lại; không tuyên bố equivalence nếu chỉ kiểm tra syntax.

## 8. Quy tắc hỗ trợ ban đầu

Ưu tiên các field thường gặp: `Image`, `CommandLine`, `ParentImage`, `OriginalFileName`, `User`. Ưu tiên modifier `endswith`, `startswith`, `contains`, `contains|all` và các condition đơn giản như `selection`, `all of selection_*`, `1 of selection*`, `selection and not filter`.

Đây là mục tiêu ưu tiên, không phải khẳng định đã hỗ trợ. Mỗi mapping cần kiểm tra tương ứng với decoder và dữ liệu thực tế. Các field khác hoặc condition phức tạp phải được phân loại rõ ràng.

## 9. Tiêu chí nghiệm thu tổng thể

1. Có thể thu thập lại dataset từ repository chính thức và chứng minh commit/checksum.
2. Mọi file trong manifest tồn tại; file YAML parse được hoặc có lỗi được ghi nhận.
3. Unit tests chạy bằng một lệnh tài liệu hóa.
4. Không sinh XML cho case unsupported nếu chưa có biểu diễn tương đương.
5. XML sinh ra well-formed; trong phase lab, Wazuh chấp nhận rule.
6. Báo cáo thể hiện kết quả theo từng rule và summary nhất quán.
7. Telegram (chỉ ở phase tương ứng) không làm lộ token và lỗi Telegram không làm hỏng conversion batch.
