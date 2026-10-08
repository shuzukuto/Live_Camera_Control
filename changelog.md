# Changelog

Lịch sử thay đổi và nâng cấp của Hệ thống Giám sát & Ghi hình Camera Tập trung (NVR/VMS Console).

## [v1.0.1] - 2026-10-08 21:05:00

### User Request
> sửa lại giao diện
> thay đổi cổng mặc định tránh trùng với các project, app khác

### Changed
- Cập nhật cổng mặc định hệ thống từ `8000` sang `8090` (`http://localhost:8090/`) tránh xung đột cổng với các dự án/ứng dụng khác (như hệ thống `Hikvision_Monitoring_System` đang dùng cổng 8000 trên máy chủ NAS); cập nhật đồng bộ trong `backend/app/config.py`, `run.py`, `start.bat`, `start.sh`, `docker-compose.yml`, `Dockerfile` và test suites.
- Mở rộng Content Security Policy (CSP) trong `backend/app/main.py` cho phép script từ Tailwind CDN và font từ Google Fonts.

### Fixed
- Khắc phục triệt để lỗi vỡ bố cục giao diện và phóng đại icon SVG chiếm toàn bộ màn hình:
  - Tái thiết kế file `backend/app/static/style.css` thành hệ thống bảng kiểu 100% tự trị (self-contained), tích hợp đầy đủ hệ thống utility class Flexbox, Grid, Modal Dialog, PTZ Joystick, Bảng nhật ký sự kiện, Glassmorphism, thanh cuộn tùy biến, đảm bảo giao diện hiển thị sắc nét kể cả khi hoạt động hoàn toàn offline không có Internet.
  - Triển khai cơ chế bảo vệ kích thước SVG kép: bổ sung thuộc tính cứng `width` và `height` trên toàn bộ thẻ `<svg>` trong `index.html` và sinh động trong `app.js`, đồng thời áp đặt giới hạn kích thước với `!important` trong CSS.
  - Sửa lỗi các cửa sổ popup modal (Quản lý thiết bị, Thư viện media, Lightbox) không ẩn do thiếu luật định kiểu `.hidden`.

### Files touched
- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/static/index.html`
- `backend/app/static/style.css`
- `backend/app/static/app.js`
- `run.py`
- `start.bat`
- `start.sh`
- `docker-compose.yml`
- `Dockerfile`
- `tests_e2e/test_tier1_features.py`
- `tests_e2e/test_tier2_boundaries.py`
- `rules.md`
- `changelog.md`

## [v1.0.0] - 2026-10-08 20:35:00

### User Request
> Viết cho tôi ứng dụng để xem và lưu video từ camera của EZVIZ, Xiaomi ( chạy server mainland china và quốc tế ),... và các camera của hãng khác.
> Tính năng:
> - Đăng nhập: sử dụng tài khoản tương ứng của các nhà cung cấp
> - Hoạt động local trực tiếp hoặc qua docker
> - Xem camera trực tiếp qua internet không giới hạn thời gian
> - Tùy chọn lưu video, ảnh theo thời gian thực
> - Lưu log event: Date Time | Event type ( Human/Movement/Abnormal Sound )

### Added
- [Hạ tầng Lõi & Bảo mật]: Xây dựng ứng dụng FastAPI backend với cơ chế mã hóa AES-256-GCM Vault (600,000 PBKDF2 iterations) để lưu trữ an toàn thông tin tài khoản camera; cơ sở dữ liệu SQLite chạy chế độ WAL mode tối ưu ghi đồng thời.
- [Đám mây EZVIZ & Xiaomi]: Tích hợp module kết nối đám mây EZVIZ OpenAPI (tự động gia hạn token, PTZ, URL luồng) và Xiaomi Mi Home Cloud hỗ trợ trọn vẹn 6 cụm máy chủ khu vực (Mainland China `cn`, Singapore `sg`, United States `us`, Germany `de`, Russia `ru`, India `i2`) kèm cơ chế ký số HMAC-SHA256 cho các truy vấn MIoT.
- [Generic IP Camera & ONVIF]: Tích hợp module quét thiết bị tự động qua WS-Discovery UDP multicast (`239.255.255.250:3702`), lấy profile SOAP và kết nối RTSP/Substream chuẩn.
- [Media Gateway & StreamKeeper 24/7]: Tích hợp media server `go2rtc` v1.9.14 nhúng kèm hỗ trợ WebRTC sub-200ms latency và MSE/HLS; daemon `StreamKeeper` tự động gia hạn phiên ngầm và hot-swap luồng giúp xem trực tiếp 24/7 không giới hạn thời gian (bypass timeout 5-10 phút của cloud).
- [NVR Real-Time & Snapshot]: Động cơ ghi hình fMP4 (fragmented MP4) chống lỗi hỏng tệp khi mất nguồn đột ngột, tối ưu tua xem `faststart`, hỗ trợ ghi hình thủ công và theo lịch; dịch vụ chụp ảnh snapshot độ phân giải cao có watermark HUD thời gian thực và tự động dọn dẹp dung lượng xoay vòng FIFO.
- [AI Event Logging]: Chuẩn hóa 3 nhóm sự kiện AI (`Human`, `Movement`, `Abnormal Sound`) từ mọi camera, lập chỉ mục ghép trên SQLite, công cụ tìm kiếm toàn trường (Universal Search), phát sóng cảnh báo thời gian thực qua WebSocket (`/api/ws/events`) và SSE (`/api/events/stream`), xuất dữ liệu 3 chế độ (Template, Bảng lọc, Toàn bộ) định dạng CSV/XLSX chống mã độc bảng tính.
- [Dashboard UI/UX Pro Max]: Giao diện giám sát Web hiện đại phong cách Dark Theme Glassmorphism công nghệ cao, lưới đa kênh linh hoạt (1x1, 2x2, 3x3, 4x4, 1+5), bộ điều khiển 8 hướng PTZ có watchdog an toàn 3s, OSD telemetry HUD hiển thị FPS/Bitrate/Độ trễ.
- [Đóng gói Triển khai]: Cung cấp đầy đủ `Dockerfile`, `docker-compose.yml` (chế độ host network và persistent volume), cùng các script chạy trực tiếp một chạm `run.py`, `start.bat` (Windows), `start.sh` (Linux/macOS).

### Files touched
- `backend/app/main.py`
- `backend/app/config.py`
- `backend/app/database.py`
- `backend/app/vault.py`
- `backend/app/services/go2rtc_service.py`
- `backend/app/services/ffmpeg_service.py`
- `backend/app/services/ezviz_service.py`
- `backend/app/services/xiaomi_service.py`
- `backend/app/services/onvif_service.py`
- `backend/app/services/camera_sync_service.py`
- `backend/app/services/stream_keeper.py`
- `backend/app/services/nvr_service.py`
- `backend/app/services/storage_service.py`
- `backend/app/services/event_service.py`
- `backend/app/services/broadcast_service.py`
- `backend/app/api/cameras.py`
- `backend/app/api/accounts.py`
- `backend/app/api/nvr.py`
- `backend/app/api/events.py`
- `backend/app/api/ws.py`
- `backend/app/static/index.html`
- `backend/app/static/style.css`
- `backend/app/static/app.js`
- `Dockerfile`
- `docker-compose.yml`
- `run.py`
- `start.bat`
- `start.sh`
- `requirements.txt`
