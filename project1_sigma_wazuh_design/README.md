# Project I — Sigma-to-Wazuh Rule Converter

Bộ tài liệu thiết kế trước khi triển khai: SRS, SAD, kế hoạch theo phase và hướng dẫn tạo bộ dữ liệu SigmaHQ có thể tái tạo.

## Nội dung
- `docs/SRS.md` — Software Requirements Specification.
- `docs/SAD.md` — Software Architecture Document.
- `docs/PHASE_PLAN.md` — Kế hoạch triển khai và tiêu chí nghiệm thu.
- `docs/DATASET_GUIDE.md` — Quy trình lấy, kiểm tra, đóng băng phiên bản và tuyển chọn bộ test.
- `scripts/collect_sigma_rules.sh` — Sparse checkout đúng thư mục nguồn từ SigmaHQ.
- `scripts/validate_sigma_dataset.py` — Kiểm tra file YAML, metadata, logsource và ID trùng; dùng pySigma nếu đã cài.
- `scripts/build_manifest.py` — Tạo manifest có SHA-256 và thông tin nguồn.

## Trạng thái bộ rule
Tệp này **không giả vờ chứa bản sao các rule SigmaHQ**. Môi trường tạo tài liệu hiện tại không thể truy cập trực tiếp GitHub để tải toàn bộ thư mục. Hãy chạy quy trình trong `docs/DATASET_GUIDE.md` trên máy Ubuntu có Internet. Quy trình sẽ tải dữ liệu thật, ghi commit SHA, kiểm tra file tồn tại và tạo manifest; không dùng danh sách tên rule tự bịa.

## Quy tắc dữ liệu
- Nguồn chính thức: https://github.com/SigmaHQ/sigma
- Thư mục: `rules/windows/process_creation/`
- Giữ nguyên file nguồn; không sửa rule upstream trong bộ dữ liệu gốc.
- Không loại rule chỉ vì converter hiện tại chưa hỗ trợ. Gắn nhãn kết quả trong manifest/coverage report.
- Phân biệt `source_valid` (rule hợp lệ theo Sigma) với `converter_supported` (hệ thống có hỗ trợ chuyển đổi hay không).
- Bộ corpus toàn thư mục dùng để đánh giá độ bao phủ; bộ smoke/regression nhỏ dùng để phát triển theo từng tính năng.
