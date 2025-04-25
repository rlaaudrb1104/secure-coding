-- init_db.sql: 데이터베이스 및 테이블 초기화 스크립트
CREATE DATABASE IF NOT EXISTS trading
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
USE trading;

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(50)   NOT NULL UNIQUE,
    email          VARCHAR(100)  NOT NULL UNIQUE,
    password_hash  VARCHAR(200)  NOT NULL,
    is_active      BOOLEAN       NOT NULL DEFAULT FALSE,
    is_blocked     BOOLEAN       NOT NULL DEFAULT FALSE,
    is_admin       BOOLEAN       NOT NULL DEFAULT FALSE,
    intro          VARCHAR(255) NOT NULL DEFAULT '소개글을 작성해보세요',
    balance        DECIMAL(10,2) NOT NULL DEFAULT 0,
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 상품 테이블
CREATE TABLE IF NOT EXISTS products (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seller_id    INT NOT NULL,
    title        VARCHAR(200) NOT NULL,
    description  TEXT,
    price        DECIMAL(10,2) NOT NULL,
    image_paths  JSON,
    category     VARCHAR(50),
    status       ENUM('available','sold','blocked') DEFAULT 'available',
    views         INT NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 메시지 테이블 (채팅)
CREATE TABLE IF NOT EXISTS messages (
    id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    room      VARCHAR(100) NOT NULL,
    sender_id INT NOT NULL,
    content   TEXT NOT NULL,
    sent_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 신고 테이블
CREATE TABLE IF NOT EXISTS reports (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    reporter_id INT NOT NULL,
    target_type ENUM('user','product') NOT NULL,
    target_id   INT NOT NULL,
    reason      VARCHAR(200),
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reporter_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 차단 테이블
CREATE TABLE IF NOT EXISTS blocks (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    target_type ENUM('user','product') NOT NULL,
    target_id   INT NOT NULL,
    blocked_by  INT NOT NULL,
    reason      VARCHAR(200),
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blocked_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 거래 테이블
CREATE TABLE IF NOT EXISTS transactions (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    from_user_id   INT NOT NULL,
    to_user_id     INT NOT NULL,
    amount         DECIMAL(10,2) NOT NULL,
    status         ENUM('pending','completed','failed') DEFAULT 'completed',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id)   REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- FULLTEXT 인덱스 (검색)
ALTER TABLE products
    ADD FULLTEXT(title, description);

INSERT INTO users (username, email, password_hash, is_active, is_admin, balance)
VALUES (
  'admin',
  'admin@example.com',
  '$2b$12$ihbliZX2WIzDnkHQOA6lsO5t6NYw82RYpD9iEY/12KQ8NpA476Wuq',  -- admin123
  TRUE,
  TRUE,
  10000000
);

INSERT INTO users (username, email, password_hash, is_active, is_admin, balance)
VALUES (
  'test1',
  'rlaaudrb1104@naver.com',
  '$2b$12$ihbliZX2WIzDnkHQOA6lsO5t6NYw82RYpD9iEY/12KQ8NpA476Wuq',  -- admin123
  TRUE,
  FALSE,
  10000000
);

INSERT INTO users (username, email, password_hash, is_active, is_admin, balance)
VALUES (
  'test2',
  'rlaaudrb1104@gmail.com',
  '$2b$12$ihbliZX2WIzDnkHQOA6lsO5t6NYw82RYpD9iEY/12KQ8NpA476Wuq',  -- admin123
  TRUE,
  FALSE,
  10000000
);