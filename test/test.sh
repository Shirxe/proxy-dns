#!/bin/bash

PORT=9898

# A - IPv4
# AAAA - IPv6
FLAGS=A



DOMAINS=(
    "mysite.dp"
    "mysite.dp.ua"
    "api.mysite.dp"
    "api.mysite.dp.ua"
    "api.mysite.dp.ua.xd"
    "subdomain.api.mysite.dp.ua.xd"
    "google.com"
    "api.google.com"
    "youtube.com"
)

../build/dns_proxy -p "$PORT" > /dev/null 2>&1 &
PROXY_PID=$!


echo "server is started"

cleanup() {
    echo "Stopping proxy dns (PID $PROXY_PID)..."
    kill $PROXY_PID
}
trap cleanup EXIT

sleep 1

for domain in "${DOMAINS[@]}"; do
    output=$(dig "$FLAGS" "$domain" @127.0.0.1 -p "$PORT")
    status=$(echo "$output" | sed -n 's/.*status: \([A-Z]*\).*/\1/p')

    if [[ "$status" == "NOERROR" ]]; then
        ip=$(echo "$output" | awk -v flag="$FLAGS" '
            /^;; ANSWER SECTION:/ {in_section=1; next}
            /^;;/ {in_section=0}
            in_section && $4==flag {print $5; exit}
        ')

        if [[ -z "$ip" ]]; then
            printf "%-35s %s\n" "$domain" "NOERROR | NOIP"
        else
            printf "%-35s %s\n" "$domain" "$ip"
        fi
    else
        printf "%-35s %s\n" "$domain" "$status"
    fi
done
