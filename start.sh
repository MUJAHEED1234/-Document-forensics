#!/usr/bin/env bash
set -euo pipefail

export PORT="${PORT:-8080}"
envsubst '${PORT}' \
    < /etc/nginx/templates/forensai.conf.template \
    > /etc/nginx/conf.d/default.conf
rm -f /etc/nginx/sites-enabled/default

cd /app/backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 &
backend_pid=$!
nginx_pid=""

shutdown() {
    if [[ -n "${nginx_pid}" ]]; then
        kill "${nginx_pid}" 2>/dev/null || true
    fi
    kill "${backend_pid}" 2>/dev/null || true
    wait "${backend_pid}" 2>/dev/null || true
}
trap shutdown TERM INT

ready=0
for _ in $(seq 1 120); do
    if ! kill -0 "${backend_pid}" 2>/dev/null; then
        echo "FORENSAI backend exited before becoming ready."
        exit 1
    fi
    if (echo > /dev/tcp/127.0.0.1/8000) 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done

if [[ "${ready}" -ne 1 ]]; then
    echo "FORENSAI backend did not become ready within 120 seconds."
    exit 1
fi

nginx -g 'daemon off;' &
nginx_pid=$!

set +e
wait -n "${backend_pid}" "${nginx_pid}"
status=$?
set -e
shutdown
exit "${status}"
