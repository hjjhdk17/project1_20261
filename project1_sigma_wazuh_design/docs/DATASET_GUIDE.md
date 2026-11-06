# Dataset Guide — SigmaHQ Windows Process Creation Rules

## 1. Mục tiêu và hai bộ dữ liệu

Không nên dùng một file text chứa 100 tên rule làm nguồn sự thật. Nguồn sự thật phải là các file YAML thực sự được lấy từ repository và có manifest.

Tạo hai bộ:

### A. Full source corpus
Toàn bộ file `.yml`/`.yaml` nằm trực tiếp trong `rules/windows/process_creation/` tại một commit SigmaHQ được ghi lại. Đây là tập để khảo sát độ bao phủ. Không loại rule chỉ vì converter chưa hỗ trợ.

### B. Curated regression suite
Một tập nhỏ được chọn có chủ đích để bao phủ feature: field, modifier, list values, AND/OR/NOT, filters, condition wildcard, missing/optional metadata, và các trường hợp unsupported. Mỗi rule có lý do chọn và expected support classification. Không tuyên bố đủ 100 rule nếu chưa kiểm tra feature coverage.

Các rule có YAML/pySigma error vẫn được ghi trong manifest với trạng thái lỗi, không xóa âm thầm. Một “clean dataset” cần minh bạch: mọi file tồn tại; mọi file có parse error được liệt kê; các rule hợp lệ nhưng chưa hỗ trợ conversion vẫn được giữ.

## 2. Lấy dữ liệu bằng sparse checkout

Trên Ubuntu Host, chạy:

```bash
mkdir -p ~/project1-datasets
cd ~/project1-datasets

git clone --filter=blob:none --no-checkout https://github.com/SigmaHQ/sigma.git sigmahq
cd sigmahq
git sparse-checkout init --cone
git sparse-checkout set rules/windows/process_creation
git checkout master

git rev-parse HEAD
find rules/windows/process_creation -maxdepth 1 -type f \\( -name '*.yml' -o -name '*.yaml' \\) | sort | wc -l
```

Đây là snapshot từ branch `master` tại thời điểm checkout. Ghi commit SHA vào báo cáo. Khi bắt đầu đánh giá chính thức, nên đổi sang commit SHA cụ thể thay vì phụ thuộc branch đang thay đổi.

Nếu cần dataset có thể tái tạo, clone lại đúng commit:
```bash
git checkout <COMMIT_SHA>
```

## 3. Tạo bản sao trong dự án

Từ thư mục repository, ví dụ:
```bash
PROJECT_ROOT="$HOME/path/to/sigma-wazuh-converter"
mkdir -p "$PROJECT_ROOT/input/sigma_rules/windows/process_creation"
cp -a rules/windows/process_creation/. \
  "$PROJECT_ROOT/input/sigma_rules/windows/process_creation/"
```

Không copy file ngoài thư mục mục tiêu vào corpus chính. Nếu Sigma rule tham chiếu các file filter/external configuration, ghi nhận dependency đó; không giả định rule độc lập hoàn toàn.

## 4. Tạo môi trường kiểm tra

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pysigma pyyaml
```

Nếu `python3` trên máy đang là phiên bản rất mới hoặc dependency có xung đột, tạo môi trường Python 3.11/3.12 riêng theo yêu cầu tương thích đã xác minh. Không thay phiên bản runtime của hệ thống tùy tiện.

Chạy validator:
```bash
python scripts/validate_sigma_dataset.py \
  --root "$PROJECT_ROOT/input/sigma_rules/windows/process_creation" \
  --output "$PROJECT_ROOT/reports/dataset-validation.json"
```

Tạo manifest:
```bash
python scripts/build_manifest.py \
  --root "$PROJECT_ROOT/input/sigma_rules/windows/process_creation" \
  --source-repo https://github.com/SigmaHQ/sigma \
  --source-commit <COMMIT_SHA> \
  --output "$PROJECT_ROOT/input/sigma_rules/manifest.json"
```

Lưu ý: validator này là lớp kiểm tra dữ liệu cho dự án; nó không thay thế toàn bộ SigmaHQ lint/validation suite. Nếu dùng pySigma, API phải được kiểm chứng với phiên bản đã pin. Khi API parse không tương thích, ghi lỗi và sửa script có test, không bỏ qua lỗi.

## 5. Quy trình xác minh “không có rule không tồn tại”

1. Mọi đường dẫn lấy từ manifest phải trỏ đến file tồn tại.
2. Chỉ thu thập file YAML có trong Git tree tại commit được ghi.
3. Lưu `git rev-parse HEAD`.
4. Lưu SHA-256 từng file.
5. Kiểm tra YAML và parse bằng pySigma.
6. Kiểm tra duplicate Sigma `id`; ghi danh sách mọi ID trùng.
7. Kiểm tra logsource `product: windows`, `category: process_creation`; các trường hợp không đúng phải được đánh dấu, không tự sửa.
8. Xuất báo cáo tổng: discovered, parsed, parse_failed, duplicate_id, missing_metadata, logsource_mismatch.
9. Không dùng title hoặc filename như một ID duy nhất.
10. Khi cập nhật dataset, tạo manifest mới; không ghi đè snapshot cũ mà không ghi lịch sử.

## 6. Chọn curated regression suite

Không chọn chỉ theo tên kiểu `whoami`, `net user`, `schtasks`: SigmaHQ có thể không có rule tên đó hoặc có thể đổi tên. Tìm theo nội dung và kiểm tra file thực tế.

Gợi ý tiêu chí tuyển chọn:
- Rule đơn giản có một selection và một field.
- `Image` hoặc `OriginalFileName`.
- `CommandLine|contains`.
- `endswith` và `startswith`.
- `contains|all`.
- Nhiều giá trị OR trong một field.
- Nhiều field kết hợp AND.
- `1 of selection_*`.
- `all of selection_*`.
- `selection and not filter`.
- Có nhiều filter hoặc condition lồng nhau (để kiểm tra UNSUPPORTED nếu ngoài phạm vi).
- Rule có field ít phổ biến (để kiểm tra unsupported rõ ràng).
- Rule có metadata optional/related/derived nếu có trong corpus.

Chọn dựa trên feature inventory được tạo từ dữ liệu thực. Mỗi record trong `curated_selection.csv` cần: relative_path, Sigma ID, title, features, expected_status, rationale. Không mặc định 100 rule là bắt buộc; nếu dự án cần đúng 100, chỉ chốt sau khi xác minh đủ 100 file thật và đa dạng feature.

## 7. Nội dung manifest khuyến nghị

- source_repo
- source_commit
- collected_at_utc
- relative_path
- file_sha256
- sigma_id
- title
- logsource
- parse_status
- parse_error
- features
- curated_suite (true/false)
- expected_support_status
- selection_rationale
