FROM python:3.11-slim-bookworm


WORKDIR /app

# System deps required by the malware-scan ML stack:
#   - libgomp1: required by LightGBM / XGBoost at runtime (OpenMP runtime)
#   - libstdc++6 is already in slim-bookworm, but we pin -dev for any C-extensions
# These add ~8 MB and let the PE-malware models actually load.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD python init_db.py && gunicorn -b 0.0.0.0:5000 app:app
