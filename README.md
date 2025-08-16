# Auth Project

## Giới thiệu
`Auth Project` là hệ thống API xác thực người dùng cho ứng dụng web/API, với các tính năng:

- Đăng ký và đăng nhập bằng **username/password**
- Đăng nhập/Đăng ký bằng **Google OAuth2 / OIDC**
- **JWT token** cho xác thực API
- **Xác thực email** khi đăng ký tài khoản thường
- Hỗ trợ bảo mật secrets qua `.env` file

---

## Công nghệ sử dụng

- Java 17  
- Spring Boot 3.x  
- Spring Security + OAuth2 / OIDC  
- Spring Data JPA + Hibernate  
- H2 / MySQL  
- JavaMailSender  
- JWT  
- Dotenv (`io.github.cdimascio:java-dotenv`)

---

## Cấu trúc dự án

src/main/java

├─ controller # API endpoints

├─ service # Business logic, email, JWT

├─ repository # Spring Data JPA repositories

├─ model/entity # User, Role

├─ dto # Data Transfer Objects

├─ exceptions # Handle exceptionsexceptions

└─ config # Security, OAuth2, Dotenv, Mail

---

## Cài đặt

1. Clone repository:

```bash
git clone https://github.com/tangtuan16/AuthT.git
cd Auth
Tạo file .env trong thư mục gốc:

# Database
DB_URL=jdbc:mysql://localhost:3306/auth_db
DB_USERNAME=root
DB_PASSWORD=123456

# JWT
JWT_SECRET=your_jwt_secret

# Mail
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_email_password
MAIL_FROM=your_email@gmail.com

# Google OAuth2
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

Chạy project:

Maven: mvn spring-boot:run

Gradle: ./gradlew bootRun

API server mặc định: http://localhost:8080

API Endpoints
1. Đăng ký thường (username/password)
POST /api/auth/register

Request Body:
json:
{
  "username": "tuan",
  "email": "tuantang@example.com",
  "password": "123456"
}
Khi đăng ký thành công, hệ thống gửi link xác thực qua email.

Click link để cập nhật trạng thái verified.

2. Đăng nhập thường
POST /api/auth/login

Request Body:

json:
{
  "username": "tuantang@example.com",
  "password": "123456"
}
Response:

json:
{
  "status": 200,
  "message": "success",
  "data": {
    "accessToken": "token_here",
    "refreshToken":"etc"
  }
}

3. Đăng nhập/Đăng ký Google
GET /oauth2/authorization/google

Redirect sang Google để xác thực.

Sau khi login, backend tạo tài khoản nếu chưa tồn tại và trả về JWT token.

GET /api/oauth2 (ví dụ test API)

Response:

json
{
  "status": 200,
  "message": "Success",
  "data": {
    "user": {
      "sub": "104509280079457539493",
      "email": "tuantang.aglaea@gmail.com",
      "name": "Tang Tuan",
      "picture": "...",
      "accessToken": "token_here",
      "refreshToken":"etc"
    }
  }
    "error":"null",
    "timestamp":"time"
}

4. Xác thực email
GET /api/auth/verify-email?token=<token>

Khi click link, backend validate token và cập nhật trạng thái user là verified.

5. Bảo vệ API với JWT
Các API sau khi login được bảo vệ bằng JWT token.

#JWT được gửi trong header:
Authorization: Bearer <token>

#Mail Service
Sử dụng JavaMailSender để gửi mail xác thực.

#Cấu hình đọc từ .env:
java
@Value("${MAIL_FROM}")
private String fromEmail;

#Secrets & Security

Lưu tất cả các secret (DB, JWT, Mail, Google OAuth) trong .env

Dùng Dotenv hoặc System.getenv() để Spring Boot đọc.

#Chạy project với Docker (tuỳ chọn)

Có thể đóng gói project bằng Docker:
dockerfile
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY build/libs/AuthT-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
CMD ["java","-jar","app.jar"]
