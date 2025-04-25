# Dockerfile
FROM python:3.10-slim

# 작업 디렉터리 설정
WORKDIR /usr/src/app

# 시스템 의존성 설치 (mysqlclient 빌드용 헤더 포함)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      default-libmysqlclient-dev \
      pkg-config \
      python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Python 패키지 복사 및 설치
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 복사
COPY . .

# SocketIO 및 Gunicorn 사용
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "app:app"]