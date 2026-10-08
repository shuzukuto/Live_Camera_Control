# Bảng Ánh Xạ Dữ Liệu (DATA_MAPPING.md)

Hợp đồng dữ liệu giữa UI ↔ API ↔ SQLite Database ↔ CSV/XLSX Export.

---

## 1. Bảng Sự Kiện AI (`events`)

| Thuộc tính UI | JSON Field API | Cột SQLite | Cột Xuất CSV/XLSX | Ghi chú & Kiểu dữ liệu |
| :--- | :--- | :--- | :--- | :--- |
| **Thời Gian** | `timestamp` | `timestamp` | `Date Time` | TEXT (ISO-8601 UTC hoặc epoch) |
| **Tên Camera** | `camera_name` | `camera_name` | `Camera Name` | TEXT (Tên hiển thị của camera) |
| **Loại Sự Kiện**| `event_type` | `event_type` | `Event Type` | TEXT (`Human`, `Movement`, `Abnormal Sound`) |
| **Mô Tả / Chi Tiết**| `description` | `metadata` | `Description` | TEXT (JSON metadata hoặc ghi chú) |
| **Liên Kết Ảnh** | `snapshot_url` | `snapshot_path`| `Snapshot Link` | TEXT (Đường dẫn tải ảnh `/snapshots/...`) |

### Chế Độ Xuất Dữ Liệu (Export Modes)
- **Xuất Template**: Trả về 5 cột header + 1 dòng dữ liệu mẫu minh họa.
- **Xuất Bảng Hiện Tại (Filtered)**: Trích xuất các dòng khớp bộ lọc từ khóa/thời gian đang xem.
- **Xuất Toàn Bộ (All)**: Trích xuất 100% bản ghi sự kiện có trong cơ sở dữ liệu.

---

## 2. Bảng Camera (`cameras`)

| Thuộc tính UI | JSON Field API | Cột SQLite | Ghi chú & Bảo mật |
| :--- | :--- | :--- | :--- |
| **ID Camera** | `id` | `id` | TEXT PK (Slug định danh duy nhất) |
| **Tên Camera** | `name` | `name` | TEXT (Tên người dùng đặt) |
| **Hãng Sản Xuất** | `vendor` | `vendor` | TEXT (`ezviz`, `xiaomi`, `generic`, `onvif`) |
| **Tài Khoản Liên Kết** | `account_id` | `account_id` | TEXT (Khóa ngoại trỏ bảng `accounts`) |
| **Địa Chỉ IP** | `ip_address` | `ip_address` | TEXT (Địa chỉ IP trong LAN nếu có) |
| **Luồng Chính** | `mainstream_url`| `mainstream_url`| TEXT (RTSP / HLS / Cloud link, đã che mật khẩu) |
| **Luồng Phụ** | `substream_url` | `substream_url` | TEXT (Luồng phụ phân giải thấp xem lưới) |
| **Trạng Thái** | `is_online` | `is_online` | INTEGER (0: Offline, 1: Online) |

---

## 3. Bảng Tài Khoản Đám Mây (`accounts`)

| Thuộc tính UI | JSON Field API | Cột SQLite | Bảo mật & Mã hóa |
| :--- | :--- | :--- | :--- |
| **ID Tài Khoản** | `id` | `id` | TEXT PK |
| **Tên Gợi Nhớ** | `name` | `name` | TEXT |
| **Nhà Cung Cấp** | `provider` | `provider` | TEXT (`ezviz`, `xiaomi`) |
| **Phân Vùng Đám Mây** | `server_region`| `server_region` | TEXT (`cn`, `sg`, `us`, `de`, `ru`, `i2`) |
| **Thông Tin Xác Thực** | `credentials` | `credentials_vault`| **MÃ HÓA AES-256-GCM** (Không lộ plaintext) |
| **Token Đang Dùng** | `token_cached` | `token_cached` | TEXT (Đã mã hóa at-rest) |

---

## 4. Bảng Bản Ghi Video NVR (`recordings`)

| Thuộc tính UI | JSON Field API | Cột SQLite | Ghi chú |
| :--- | :--- | :--- | :--- |
| **ID Bản Ghi** | `id` | `id` | TEXT PK |
| **Camera ID** | `camera_id` | `camera_id` | TEXT (Khóa ngoại) |
| **Tên Tệp Tin** | `filename` | `filename` | TEXT (Định dạng `.mp4`) |
| **Đường Dẫn Tệp** | `file_path` | `file_path` | TEXT (Đường dẫn lưu trên đĩa) |
| **Thời Lượng (giây)**| `duration_seconds`| `duration_seconds`| REAL |
| **Kích Thước (bytes)**| `size_bytes` | `size_bytes` | INTEGER |
| **Khóa Bảo Vệ** | `is_locked` | `is_locked` | INTEGER (1: Không bị FIFO xóa khi đầy ổ) |
