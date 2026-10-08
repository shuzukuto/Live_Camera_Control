# Hệ Thống Giám Sát & Ghi Hình Camera Tập Trung (Centralized Web NVR/VMS Console)

[![Version](https://img.shields.io/badge/version-v1.0.1-blue.svg)](changelog.md)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![go2rtc](https://img.shields.io/badge/go2rtc-v1.9.14-orange.svg)](https://github.com/AlexxIT/go2rtc)
[![WebRTC](https://img.shields.io/badge/WebRTC-%3C200ms%20Latency-success.svg)](https://webrtc.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Hệ thống giám sát, điều khiển và ghi hình camera tập trung hoạt động trên nền tảng Web hiện đại (NVR/VMS). Ứng dụng hỗ trợ kết nối trực tiếp đa nền tảng đám mây (**EZVIZ Open Platform**, **Xiaomi Mi Home Cloud** hỗ trợ trọn vẹn 6 cụm máy chủ toàn cầu) cùng chuẩn mở **ONVIF** và luồng **RTSP** nội bộ (Hikvision, Dahua, Imou, Yoosee, Ezviz, v.v.).

---

## Mục Lục
1. [Điểm Nổi Bật Kỹ Thuật](#-điểm-nổi-bật-kỹ-thuật)
2. [Chi Tiết Tính Năng](#-chi-tiết-tính-năng)
3. [Cấu Trúc Cổng Mạng Mặc Định](#-cấu-trúc-cổng-mạng-mặc-định)
4. [Yêu Cầu Hệ Thống](#-yêu-cầu-hệ-thống)
5. [Hướng Dẫn Cài Đặt & Khởi Chạy](#-hướng-dẫn-cài-đặt--khởi-chạy)
   - [Cách 1: Khởi chạy 1 chạm trên Windows (Native)](#cách-1-khởi-chạy-1-chạm-trên-windows-native)
   - [Cách 2: Khởi chạy trên Linux / macOS](#cách-2-khởi-chạy-trên-linux--macos)
   - [Cách 3: Triển khai qua Docker & Docker Compose](#cách-3-triển-khai-qua-docker--docker-compose)
6. [Hướng Dẫn Sử Dụng Chi Tiết](#-hướng-dẫn-sử-dụng-chi-tiết)
   - [1. Kết nối Tài khoản EZVIZ Open Platform](#1-kết-nối-tài-khoản-ezviz-open-platform)
   - [2. Kết nối Tài khoản Xiaomi Mi Home Cloud](#2-kết-nối-tài-khoản-xiaomi-mi-home-cloud)
   - [3. Thêm Camera IP Generic & Tự động quét ONVIF LAN](#3-thêm-camera-ip-generic--tự-động-quét-onvif-lan)
   - [4. Xem Camera Trực Tiếp & Đổi Bố Cục Lưới](#4-xem-camera-trực-tiếp--đổi-bố-cục-lưới)
   - [5. Điều Khiển Xoay / Nghiêng / Thu Phóng (PTZ)](#5-điều-khiển-xoay--nghiêng--thu-phóng-ptz)
   - [6. Ghi Hình NVR Thời Gian Thực & Chụp Ảnh Snapshot](#6-ghi-hình-nvr-thời-gian-thực--chụp-ảnh-snapshot)
   - [7. Giám Sát Nhật Ký Sự Kiện AI & Xuất Dữ Liệu](#7-giám-sát-nhật-ký-sự-kiện-ai--xuất-dữ-liệu)
7. [Bảo Mật & Két Khóa Thông Tin Mật (Vault)](#-bảo-mật--két-khóa-thông-tin-mật-vault)
8. [Danh Sách API Chính (RESTful & WebSocket)](#-danh-sách-api-chính-restful--websocket)
9. [Biến Môi Trường Cấu Hình (.env)](#-biến-môi-trường-cấu-hình-env)
10. [Xử Lý Sự Cố Thường Gặp (Troubleshooting)](#-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## 🚀 Điểm Nổi Bật Kỹ Thuật

- **WebRTC Siêu Trễ Thấp (< 200ms)**: Sử dụng media server `go2rtc` v1.9.14 nhúng kèm, truyền tải luồng video qua giao thức WebRTC trực tiếp tới trình duyệt mà không cần cài đặt plugin hay phần mềm phụ trợ. Tự động dự phòng sang fMP4 (MSE)/HLS khi trình duyệt không hỗ trợ WebRTC.
- **StreamKeeper 24/7 (Xem Trực Tiếp Không Giới Hạn)**: Đám mây EZVIZ và Xiaomi thường tự ngắt luồng sau 5-10 phút để tiết kiệm tài nguyên máy chủ. Cơ chế ngầm `StreamKeeper` chủ động gia hạn token và hoán đổi URL luồng (hot-swap) trước 30 giây, giúp việc giám sát liên tục 24/7 không bị gián đoạn.
- **Ưu Tiên Luồng Mạng Nội Bộ (LAN RTSP Fallback)**: Tự động trích xuất và ưu tiên luồng RTSP nội bộ nếu camera cùng lớp mạng, loại bỏ phụ thuộc vào băng thông Internet ra ngoài.
- **Động Cơ Ghi Hình Chống Lỗi fMP4**: Video được ghi theo định dạng Fragmented MP4 (fMP4), chống triệt để tình trạng tệp tin bị hỏng khi mất điện, tắt đột ngột hoặc rớt mạng. Tự động phục hồi và remux metadata `faststart` khi khởi động.
- **Két Mã Hóa Chuẩn Quân Đội (AES-256-GCM Vault)**: Toàn bộ mật khẩu, AppKey, AppSecret, Xiaomi Service Token được mã hóa AES-256-GCM với 600,000 vòng lặp PBKDF2 (chuẩn OWASP), khóa mã hóa lưu cách ly trong `data/` không bao giờ gửi ra trình duyệt.
- **Cổng Mặc Định 8090 Độc Lập**: Hoạt động mặc định tại cổng **`8090`** (`http://localhost:8090/`), triệt tiêu xung đột với các ứng dụng khác đang chiếm cổng 8000 (như Django, default FastAPI, Hikvision Monitoring Server,...).
- **Giao Diện Dark Glassmorphism Tự Trị (100% Self-Contained)**: Thiết kế chuẩn **UI/UX Pro Max**, toàn bộ style CSS được đóng gói khép kín trong `style.css`, bảo vệ kích thước SVG icon không bao giờ bị vỡ hạt hay phóng đại kể cả khi chạy trong mạng LAN cô lập không có Internet.

---

## 🎯 Chi Tiết Tính Năng

| Module | Chức Năng Chính | Mô Tả Kỹ Thuật |
| :--- | :--- | :--- |
| **EZVIZ Cloud** | Đồng bộ camera & điều khiển | Kết nối Open Platform API, tự động làm mới Access Token, lấy luồng HLS/RTSP/RTMP, điều khiển PTZ đám mây. |
| **Xiaomi Mi Home** | Hỗ trợ 6 Server Region | Hỗ trợ đăng nhập qua Xiaomi Passport, ký số HMAC-SHA256, hỗ trợ 6 khu vực máy chủ: `cn` (Nội địa TQ), `sg` (Singapore/ĐNÁ), `us` (Mỹ), `de` (Châu Âu), `ru` (Nga), `i2` (Ấn Độ). |
| **ONVIF & Generic IP** | Tự động dò quét & RTSP | Tự động dò tìm camera qua UDP Multicast WS-Discovery (`239.255.255.250:3702`), lấy profile SOAP và URL luồng RTSP chuẩn. Tự động che mờ (mask) mật khẩu RTSP. |
| **Dashboard Console** | Lưới xem đa kênh | Hỗ trợ 5 chế độ bố cục linh hoạt: **1x1**, **2x2**, **3x3**, **4x4** và **1+5** (1 camera chính lớn + 5 camera phụ nhỏ xung quanh). |
| **PTZ Control Deck** | Điều khiển xoay 8 hướng | Bàn phím điều khiển xoay 8 hướng (▲ ▼ ◀ ▶ và 4 góc chéo), dừng khẩn cấp STOP, thanh trượt chỉnh tốc độ (1-10), Zoom In/Out, cơ chế watchdog tự ngắt sau 3 giây an toàn. |
| **NVR Recorder** | Ghi hình theo thời gian thực | Ghi video fMP4 1080p/720p, hỗ trợ ghi thủ công từng camera, hiển thị huy hiệu REC nhấp nháy, kiểm tra dung lượng ổ đĩa tự động dọn dẹp xoay vòng FIFO. |
| **Snapshot Engine** | Chụp ảnh & Watermark HUD | Chụp khung hình chất lượng cao kèm Watermark hiển thị Tên camera + Thời gian thực, sinh thumbnail tự động, tích hợp Lightbox phóng to. |
| **AI Event Logging** | Nhật ký sự kiện AI chuẩn hóa | Chuẩn hóa 3 nhóm sự kiện: `Human` (Người), `Movement` (Chuyển động), `Abnormal Sound` (Âm thanh bất thường). Phát chuông báo động Web Audio phân biệt cao độ. |
| **Universal Search & Export** | Tìm kiếm toàn trường & Xuất file | Tìm kiếm tức thì trên mọi trường dữ liệu. Xuất báo cáo 3 chế độ (**Template**, **Bảng lọc**, **Toàn bộ**) định dạng CSV/Excel (.xlsx) có cơ chế chặn Formula Injection. |

---

## 🔌 Cấu Trúc Cổng Mạng Mặc Định

| Cổng | Giao Thức | Dịch Vụ / Vai Trò | Ghi Chú |
| :---: | :---: | :--- | :--- |
| **`8090`** | TCP (HTTP/WS) | **Web Surveillance Dashboard & REST API** | Truy cập tại `http://localhost:8090/` (thay thế 8000 tránh xung đột) |
| **`1984`** | TCP (HTTP) | **go2rtc API / WHEP SDP Exchange** | Endpoint quản lý luồng và WebRTC handshake |
| **`8554`** | TCP/UDP | **RTSP Relay Server** | Luồng RTSP chuyển tiếp nội bộ |
| **`8555`** | TCP/UDP | **WebRTC PeerConnection Media** | Luồng truyền tải video/audio WebRTC thời gian thực |

> **Mẹo**: Nếu muốn đổi cổng Web sang cổng khác (ví dụ `8899`), chỉ cần chạy:
> ```bash
> python run.py --port 8899
> ```
> Hoặc đặt biến môi trường `PORT=8899` trong tệp `.env`.

---

## 💻 Yêu Cầu Hệ Thống

- **Hệ điều hành**: Windows 10/11, Windows Server, Linux (Ubuntu, Debian, CentOS, Alpine), macOS.
- **Python**: 3.10 trở lên (khuyến nghị Python 3.11 hoặc 3.12).
- **FFmpeg**: Phiên bản 5.0+ hoặc 7.1+ (Hệ thống tự động sử dụng `imageio-ffmpeg` đi kèm trong Python, hoặc nhận diện FFmpeg có sẵn trên PATH hệ điều hành).
- **Dung lượng ổ cứng**: Tối thiểu 20 GB khả dụng để lưu trữ video ghi hình và ảnh chụp.

---

## 📦 Hướng Dẫn Cài Đặt & Khởi Chạy

### Cách 1: Khởi chạy 1 chạm trên Windows (Native)

Nhấp đúp chuột vào tệp tin **`start.bat`** tại thư mục gốc của dự án. 
Script sẽ tự động:
1. Tạo môi trường ảo Python `.venv` nếu chưa có.
2. Cài đặt toàn bộ thư viện cần thiết từ `requirements.txt`.
3. Tải tự động binary `go2rtc.exe` phiên bản chính thức v1.9.14 vào thư mục `bin/`.
4. Khởi chạy máy chủ tại **`http://localhost:8090/`** và tự động mở trình duyệt web.

```cmd
start.bat
```

---

### Cách 2: Khởi chạy trên Linux / macOS

Cấp quyền thực thi và chạy tệp **`start.sh`**:

```bash
chmod +x start.sh
./start.sh
```

Hoặc thực hiện thủ công bằng lệnh Python:

```bash
# 1. Tạo và kích hoạt môi trường ảo
python3 -m venv .venv
source .venv/bin/activate

# 2. Cài đặt thư viện
pip install -r requirements.txt

# 3. Khởi chạy ứng dụng (cổng 8090)
python run.py
```

---

### Cách 3: Triển khai qua Docker & Docker Compose

Ứng dụng cung cấp sẵn `Dockerfile` đa nền tảng và `docker-compose.yml` tối ưu cho NAS/Server:

```bash
# Khởi chạy ở chế độ nền
docker compose up -d --build
```

Kiểm tra trạng thái container:
```bash
docker compose ps
docker compose logs -f nvr-console
```

Truy cập giao diện: **`http://<IP-của-máy-chủ>:8090/`**

---

## 📖 Hướng Dẫn Sử Dụng Chi Tiết

### 1. Kết nối Tài khoản EZVIZ Open Platform

1. Nhấp vào nút **`+ Thêm Thiết bị / Cloud`** trên thanh công cụ góc trên bên phải.
2. Chọn tab **`Tài Khoản EZVIZ`**.
3. Điền thông tin:
   - **Tên Gợi Nhớ Tài Khoản**: ví dụ `Camera EZVIZ Nhà Riêng`.
   - **AppKey**: Lấy từ cổng nhà phát triển EZVIZ Open Platform ([open.ys7.com](https://open.ys7.com/)).
   - **AppSecret**: Khóa bí mật đi kèm.
4. Nhấn **`Lưu & Đồng Bộ EZVIZ`**.
5. Hệ thống sẽ tự động xác thực, lấy Access Token và đồng bộ toàn bộ danh sách camera kèm trạng thái luồng vào bảng điều khiển.

---

### 2. Kết nối Tài khoản Xiaomi Mi Home Cloud

1. Mở cửa sổ **`Quản Lý Tài Khoản Cloud & Camera`** -> chọn tab **`Tài Khoản Xiaomi`**.
2. Điền thông tin:
   - **Tên Gợi Nhớ**: ví dụ `Xiaomi Camera Văn Phòng`.
   - **Tên đăng nhập**: Email, Số điện thoại (kèm mã quốc gia ví dụ `+84...`) hoặc Mi ID.
   - **Mật khẩu**: Mật khẩu tài khoản Xiaomi Mi Home.
   - **Phân Vùng Máy Chủ (Server Region)**: Chọn đúng cụm máy chủ mà thiết bị đã được kích hoạt:
     - `Mainland China (cn)`: Dành cho camera bản nội địa Trung Quốc.
     - `Singapore / Đông Nam Á (sg)`: Dành cho camera bản quốc tế tại Việt Nam / Đông Nam Á.
     - `United States (us)`, `Germany (de)`, `Russia (ru)`, `India (i2)`: Cho các khu vực tương ứng.
3. Nhấn **`Lưu & Đồng Bộ Xiaomi`**. Hệ thống sẽ đăng nhập qua Xiaomi Service Token, tự động giải mã danh sách thiết bị và đưa vào hệ thống.

---

### 3. Thêm Camera IP Generic & Tự động quét ONVIF LAN

#### Thêm thủ công qua RTSP:
1. Chọn tab **`Thêm RTSP / ONVIF`**.
2. Nhập:
   - **Tên Camera**: ví dụ `Camera Hikvision Cổng Chính`.
   - **Hãng / Vendor**: `Hikvision`, `Dahua`, `Imou`, `Yoosee`,...
   - **Luồng Chính (Mainstream RTSP)**: `rtsp://admin:MatKhau@192.168.1.100:554/Streaming/Channels/101`
   - **Luồng Phụ (Substream RTSP - tùy chọn)**: `rtsp://admin:MatKhau@192.168.1.100:554/Streaming/Channels/102`
3. Nhấn **`Thêm Camera`**.

#### Quét tự động camera ONVIF trong mạng nội bộ (WS-Discovery):
1. Chọn tab **`Quét ONVIF LAN`**.
2. Nhấn nút **`Bắt Đầu Quét`**.
3. Hệ thống sẽ phát gói tin UDP Multicast tìm kiếm toàn bộ camera ONVIF đang kết nối trong cùng mạng LAN, liệt kê IP và cổng dịch vụ để bạn nhập tài khoản/mật khẩu và kết nối với 1 click.

---

### 4. Xem Camera Trực Tiếp & Đổi Bố Cục Lưới

- **Chuyển đổi bố cục xem**: Trên thanh điều khiển trên cùng, chọn các nút chế độ:
  - **`1x1`**: Xem 1 camera toàn màn hình lớn nhất.
  - **`2x2`**: Lưới 4 camera tiêu chuẩn.
  - **`3x3`**: Lưới 9 camera.
  - **`4x4`**: Lưới 16 camera giám sát diện rộng.
  - **`1+5`**: Chế độ tiêu điểm (1 ô lớn chiếm 2/3 màn hình và 5 ô nhỏ xung quanh).
- **Gán camera vào ô**: 
  - Tại thanh danh sách kênh bên phải, nhấp vào camera bất kỳ để chọn làm camera mục tiêu.
  - Nhấp vào biểu tượng Play cạnh tên camera để gán trực tiếp vào ô số 1.
  - Nhấp trực tiếp vào ô camera trên lưới để kích hoạt điều khiển PTZ cho camera đó (viền xanh sáng lên).

---

### 5. Điều Khiển Xoay / Nghiêng / Thu Phóng (PTZ)

1. Chọn camera có hỗ trợ xoay quét (PTZ) trên lưới hoặc trong danh sách kênh.
2. Chuyển sang tab **`Điều Khiển PTZ`** tại thanh bên phải.
3. Thao tác điều khiển:
   - **Xoay 4 hướng chính**: Nhấn giữ nút **▲** (Lên), **▼** (Xuống), **◀** (Trái), **▶** (Phải).
   - **Dừng khẩn cấp**: Nhấn nút tròn **`STOP`** ở giữa bàn xoay.
   - **Thu Phóng (Zoom)**: Nhấn **`Zoom In (+)`** hoặc **`Zoom Out (-)`**.
   - **Điều chỉnh tốc độ**: Kéo thanh trượt **Tốc độ quay** từ `1` (chậm, chính xác) đến `10` (nhanh).
4. **Cơ chế an toàn (Watchdog)**: Khi thả chuột, lệnh dừng sẽ tự động gửi. Nếu mất kết nối, hệ thống tự động ngắt lệnh xoay sau tối đa 3 giây để tránh camera quay kịch khớp cơ khí.

---

### 6. Ghi Hình NVR Thời Gian Thực & Chụp Ảnh Snapshot

- **Ghi hình thủ công**:
  - Rê chuột vào ô camera đang xem -> thanh tác vụ nhanh sẽ trượt lên ở góc dưới bên phải ô.
  - Nhấn nút **`Ghi`** (biểu tượng chấm đỏ). Ô camera sẽ chuyển viền đỏ và hiển thị huy hiệu nhấp nháy `REC`.
  - Nhấn lại nút **`Dừng`** khi muốn kết thúc đoạn video. Tệp video fMP4 sẽ được lưu vào thư mục `recordings/`.
- **Chụp ảnh Snapshot tức thì**:
  - Nhấn biểu tượng máy ảnh trên thanh tác vụ nhanh của camera.
  - Ảnh JPEG độ phân giải gốc kèm watermark hiển thị thời gian thực sẽ được lưu vào thư mục `snapshots/`.
- **Xem lại tại Thư viện Media**:
  - Nhấn nút **`Thư viện Media`** trên header để mở kho lưu trữ video và ảnh chụp.
  - Nhấp vào ảnh để phóng to toàn màn hình qua Lightbox.

---

### 7. Giám Sát Nhật Ký Sự Kiện AI & Xuất Dữ Liệu

- **Theo dõi sự kiện thời gian thực**:
  - Chuyển sang tab **`Nhật Ký Sự Kiện`** tại thanh bên phải.
  - Hệ thống tự động thu nhận các sự kiện AI qua WebSocket:
    - 🟡 `Human`: Nhận diện người, quét chuyển động dáng người.
    - 🔵 `Movement`: Phát hiện chuyển động qua khung hình, cảm biến PIR.
    - 🟣 `Abnormal Sound`: Âm thanh bất thường (tiếng nổ, kính vỡ, tiếng trẻ em khóc,...).
  - Tự động phát âm thanh cảnh báo trực tiếp (Web Audio Synthesizer) với cao độ riêng biệt cho từng loại sự kiện.
- **Tìm kiếm toàn trường (Universal Search)**:
  - Nhập từ khóa bất kỳ vào ô tìm kiếm: hệ thống sẽ lọc tức thì trên toàn bộ các cột (tên camera, ID, ngày giờ, loại sự kiện).
  - Sử dụng các chip lọc nhanh: `Tất cả`, `Human`, `Movement`, `Sound`.
- **Xuất dữ liệu 3 chế độ**:
  - **`Template`**: Xuất tệp tin mẫu gồm tiêu đề cột và 1 dòng hướng dẫn định dạng CSV/Excel.
  - **`Bảng Lọc`**: Chỉ xuất những dòng đang hiển thị theo bộ lọc tìm kiếm hiện hành.
  - **`Toàn Bộ`**: Xuất toàn bộ cơ sở dữ liệu sự kiện từ trước đến nay (bỏ phân trang).
  - *Tích hợp sẵn bộ lọc Formula Injection bảo vệ an toàn khi mở bằng Microsoft Excel.*

---

## 🔒 Bảo Mật & Két Khóa Thông Tin Mật (Vault)

- Mật mã AEAD chuẩn **AES-256-GCM** bảo vệ tính toàn vẹn và bí mật của tài khoản camera.
- Muối mật mã ngẫu nhiên 128-bit CSPRNG kết hợp với hàm băm dẫn xuất khóa **PBKDF2-HMAC-SHA256 (600,000 vòng lặp)**.
- Khóa bảo mật được bảo vệ độc quyền trong phân vùng máy chủ, không bao giờ lộ ra phía giao diện Web.

---

## 📡 Danh Sách API Chính (RESTful & WebSocket)

| Phương thức | Endpoint | Chức Năng |
| :---: | :--- | :--- |
| `GET` | `/api/health` | Kiểm tra tình trạng sức khỏe hệ thống (DB, Vault, go2rtc, FFmpeg) |
| `GET` | `/api/cameras` | Lấy danh sách toàn bộ camera đã kết nối |
| `POST` | `/api/cameras` | Thêm camera IP / luồng RTSP thủ công |
| `DELETE` | `/api/cameras/{id}` | Xóa camera khỏi hệ thống |
| `POST` | `/api/cameras/{id}/ptz` | Điều khiển PTZ (lệnh: `up`, `down`, `left`, `right`, `stop`, `zoomin`, `zoomout`) |
| `POST` | `/api/accounts` | Thêm tài khoản đám mây (EZVIZ / Xiaomi) |
| `POST` | `/api/accounts/{id}/sync` | Đồng bộ cưỡng bức danh sách camera từ đám mây |
| `POST` | `/api/onvif/discover` | Kích hoạt quét dò tìm camera ONVIF qua UDP Multicast trên mạng LAN |
| `POST` | `/api/nvr/record/start` | Bắt đầu ghi hình video thời gian thực cho một camera |
| `POST` | `/api/nvr/record/stop` | Dừng phiên ghi hình và đóng gói container MP4 |
| `POST` | `/api/nvr/snapshot` | Chụp ảnh khung hình hiện tại có watermark OSD HUD |
| `GET` | `/api/events` | Lấy danh sách sự kiện AI (hỗ trợ phân trang, lọc loại, tìm kiếm) |
| `GET` | `/api/events/export` | Xuất dữ liệu sự kiện ra CSV hoặc XLSX (mode: `template`, `filtered`, `all`) |
| `WS` | `/api/ws/events` | Kênh WebSocket truyền nhận cảnh báo AI thời gian thực hai chiều |
| `GET` | `/api/events/stream` | Kênh Server-Sent Events (SSE) dự phòng cho WebSocket |

---

## ⚙️ Biến Môi Trường Cấu Hình (.env)

Bạn có thể tạo tệp `.env` tại thư mục gốc để ghi đè các cấu hình mặc định:

```env
# Cấu hình Mạng & Cổng
PORT=8090
HOST=0.0.0.0
DEBUG=false
ENV=production

# Lưu Trữ & NVR Retention
MAX_STORAGE_GB=500.0
MIN_FREE_SPACE_GB=20.0
RETENTION_DAYS=30

# Media Server go2rtc
GO2RTC_ENABLED=true
GO2RTC_API_URL=http://127.0.0.1:1984
GO2RTC_RTSP_URL=rtsp://127.0.0.1:8554
GO2RTC_WEBRTC_URL=http://127.0.0.1:8555

# Két Khóa Bảo Mật
VAULT_MASTER_PASSPHRASE=your_custom_secret_passphrase_here
```

---

## 🛠 Xử Lý Sự Cố Thường Gặp (Troubleshooting)

### 1. Camera không tải được hình ảnh (Màn hình đen)
- **Kiểm tra luồng RTSP**: Thử mở URL luồng bằng phần mềm VLC Media Player để xác nhận luồng camera còn hoạt động và tài khoản/mật khẩu đúng.
- **Kiểm tra go2rtc**: Đảm bảo dịch vụ go2rtc đang chạy bằng cách mở trình duyệt tới `http://localhost:1984/`. Nếu chưa chạy, ứng dụng sẽ tự động khởi động lại go2rtc.

### 2. Camera Xiaomi không đồng bộ được
- Kiểm tra lại xem bạn đã chọn đúng **Phân vùng máy chủ (Server Region)** chưa (ví dụ: camera nội địa Trung Quốc bắt buộc phải chọn `Mainland China - cn`).
- Nếu tài khoản bật xác thực 2 bước (2FA), hãy tạm tắt hoặc đăng nhập trước trên ứng dụng Mi Home cùng mạng.

### 3. Camera EZVIZ báo lỗi xác thực hoặc ngắt luồng
- Đảm bảo bạn đã bật tính năng luồng mở (Open Service) trên cổng EZVIZ Open Platform.
- StreamKeeper sẽ tự động gia hạn token, nhưng nếu bạn đổi mật khẩu trên app EZVIZ, vui lòng cập nhật lại Secret trong phần Quản lý tài khoản.

### 4. Báo lỗi xung đột cổng mạng (Port already in use)
- Ứng dụng đã chuyển mặc định sang cổng **`8090`**. Nếu cổng này vẫn bị ứng dụng khác chiếm giữ, hãy chỉ định cổng mới khi chạy:
  ```cmd
  .venv\Scripts\python.exe run.py --port 8899
  ```

---

## 📄 Bản Quyền & Giấy Phép (License)

Dự án được phân phối dưới giấy phép **MIT License**. Bạn được toàn quyền sử dụng, sửa đổi và triển khai cho mục đích cá nhân hoặc thương mại.
