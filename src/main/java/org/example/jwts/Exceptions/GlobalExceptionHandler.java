package org.example.jwts.Exceptions;

import io.jsonwebtoken.JwtException;
import org.example.jwts.DTO.ApiResponse;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.security.SignatureException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Lỗi validate @Valid
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage())
        );
        return ApiResponse.erorr("Validation failed", HttpStatus.BAD_REQUEST.value(), errors);
    }

    // Sai username hoặc password
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<String>> handleBadCredentials(BadCredentialsException ex) {
        return ApiResponse.erorr(
                "Invalid username or password",
                HttpStatus.UNAUTHORIZED.value(),
                null
        );
    }

    // Token JWT không hợp lệ hoặc hết hạn
    @ExceptionHandler({JwtException.class, SignatureException.class})
    public ResponseEntity<ApiResponse<String>> handleJwtError(RuntimeException ex) {
        return ApiResponse.erorr(
                "Invalid or expired token",
                HttpStatus.UNAUTHORIZED.value(),
                null
        );
    }


    // Lỗi nghiệp vụ & tự đoán mã lỗi
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<String>> handleRuntimeException(RuntimeException ex) {
        HttpStatus status = detectHttpStatus(ex);
        return ApiResponse.erorr(ex.getMessage(), status.value(), null);
    }

    // Lỗi không mong đợi
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<String>> handleUnexpected(Exception ex) {
        return ApiResponse.erorr("Internal Server Error", HttpStatus.INTERNAL_SERVER_ERROR.value(), null);
    }

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // true = nếu chuỗi chỉ toàn khoảng trắng → set thành null
        binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));
    }

    // Đoán mã lỗi dựa vào nội dung message
    private HttpStatus detectHttpStatus(RuntimeException ex) {
        String msg = ex.getMessage() != null ? ex.getMessage().toLowerCase() : "";

        if (msg.contains("not found")) return HttpStatus.NOT_FOUND;
        if (msg.contains("already exists") || msg.contains("duplicate")) return HttpStatus.CONFLICT;
        if (msg.contains("invalid") || msg.contains("not valid")) return HttpStatus.BAD_REQUEST;

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}

