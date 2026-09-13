# Calibre-Web 二开版（OIDC 通用登录）容器镜像
FROM python:3.12-slim

# libmagic: python-magic 运行时依赖；tzdata: 时区支持
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先装依赖，利用 Docker 层缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir "Flask-Dance>=2.0.0,<7.2.0" "SQLAlchemy-Utils>=0.33.5,<0.43.0"

# 应用源码
COPY cps.py ./
COPY cps/ cps/

# 应用数据（app.db 等）统一放 /config，配合卷挂载持久化
ENV CALIBRE_DBPATH="/config"
EXPOSE 8083
VOLUME ["/config"]

CMD ["python", "-u", "cps.py"]
