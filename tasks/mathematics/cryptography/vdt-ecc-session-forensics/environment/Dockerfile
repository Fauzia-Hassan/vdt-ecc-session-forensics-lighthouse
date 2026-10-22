FROM python:3.12.9-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    numpy==2.2.5 \
    scipy==1.15.2 \
    pandas==2.2.3 \
    pyarrow==19.0.1 \
    scikit-learn==1.6.1 \
    pytest==8.3.5

COPY data/ /app/data/
RUN mkdir -p /app/results

CMD ["/bin/bash"]
